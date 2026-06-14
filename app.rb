require 'sinatra'
require 'sqlite3'
require 'mail'
require 'json'
require 'securerandom'
require 'dotenv/load' if ENV['RACK_ENV'] != 'production'
require 'rack/cors'
require 'logger'

# ─────────────────────────────────────────
#  Configuration Sinatra
# ─────────────────────────────────────────
set :port,          ENV.fetch('PORT', 3000)
set :bind,          '0.0.0.0'
set :public_folder, File.dirname(__FILE__) + '/public'

# ─────────────────────────────────────────
#  Logger
# ─────────────────────────────────────────
LOGGER = Logger.new($stdout)
LOGGER.level = Logger::DEBUG
LOGGER.formatter = proc do |severity, datetime, _prog, msg|
  color = case severity
          when 'DEBUG' then "\e[36m"
          when 'INFO'  then "\e[32m"
          when 'WARN'  then "\e[33m"
          when 'ERROR' then "\e[31m"
          when 'FATAL' then "\e[35m"
          else "\e[0m"
          end
  "\e[0m#{color}[#{severity}]\e[0m #{datetime.strftime('%Y-%m-%d %H:%M:%S')} -- #{msg}\n"
end

# ─────────────────────────────────────────
#  CORS
# ─────────────────────────────────────────
use Rack::Cors do
  allow do
    origins '*'
    resource '*', headers: :any, methods: [:get, :post, :put, :delete, :options]
  end
end

# ─────────────────────────────────────────
#  Base de données SQLite
# ─────────────────────────────────────────
DB_PATH = File.join(File.dirname(__FILE__), 'data.db')
DB = SQLite3::Database.new(DB_PATH)
DB.results_as_hash = true

# Activer les clés étrangères (nécessaire pour ON DELETE CASCADE)
DB.execute('PRAGMA foreign_keys = ON')
DB.execute('PRAGMA journal_mode = WAL')

DB.execute_batch <<-SQL
  CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    name            TEXT,
    api_key         TEXT UNIQUE,
    smtp_host       TEXT,
    smtp_port       INTEGER,
    smtp_user       TEXT,
    smtp_pass       TEXT,
    smtp_from_email TEXT,
    smtp_from_name  TEXT,
    -- Rate limit par clé : max requêtes sur la fenêtre (NULL = désactivé)
    rate_limit_max  INTEGER DEFAULT NULL,
    -- Fenêtre glissante en secondes (défaut 3600 = 1h)
    rate_limit_window INTEGER DEFAULT 3600,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Origines HTTP autorisées à utiliser la clé (ex: https://monsite.com)
  -- Si aucune entrée pour une clé → clé utilisable depuis n'importe quelle origine (mode serveur)
  -- Si au moins une entrée → seules ces origines sont acceptées (mode browser public)
  CREATE TABLE IF NOT EXISTS allowed_origins (
    id         TEXT PRIMARY KEY,
    api_key_id TEXT,
    origin     TEXT NOT NULL,   -- ex: https://monsite.com  (sans slash final)
    label      TEXT,            -- nom lisible optionnel
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
  );

  -- Garde la table allowed_domains pour compatibilité ascendante (domaines expéditeur email)
  CREATE TABLE IF NOT EXISTS allowed_domains (
    id         TEXT PRIMARY KEY,
    api_key_id TEXT,
    domain     TEXT,
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS request_logs (
    id          TEXT PRIMARY KEY,
    api_key_id  TEXT,
    tenant_name TEXT,
    status      TEXT,
    error_msg   TEXT,
    recipient   TEXT,
    subject     TEXT,
    ip          TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Fenêtre glissante pour le rate limiting (nettoyée automatiquement)
  CREATE TABLE IF NOT EXISTS rate_limit_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,   -- 'global' ou l'api_key_id
    hit_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_rate_hits_scope_time
    ON rate_limit_hits(scope, hit_at);
SQL

# Migrations : ajouter les colonnes rate limit si elles n'existent pas (idempotent)
begin
  DB.execute('ALTER TABLE api_keys ADD COLUMN rate_limit_max INTEGER DEFAULT NULL')
rescue SQLite3::Exception
end
begin
  DB.execute('ALTER TABLE api_keys ADD COLUMN rate_limit_window INTEGER DEFAULT 3600')
rescue SQLite3::Exception
end

# Créer allowed_origins si migration depuis une ancienne version
DB.execute_batch <<-SQL
  CREATE TABLE IF NOT EXISTS allowed_origins (
    id         TEXT PRIMARY KEY,
    api_key_id TEXT,
    origin     TEXT NOT NULL,
    label      TEXT,
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_allowed_origins_key
    ON allowed_origins(api_key_id);
SQL

LOGGER.info("DB initialisée → #{DB_PATH}")
LOGGER.info("Clés chargées  → #{DB.execute('SELECT count(*) FROM api_keys').first[0]}")

# ─────────────────────────────────────────
#  Rate Limiting — Fenêtre glissante
# ─────────────────────────────────────────
#
#  Deux niveaux :
#   1. GLOBAL   : ENV['RATE_LIMIT_GLOBAL_MAX'] req / ENV['RATE_LIMIT_GLOBAL_WINDOW'] sec
#                 Protège le serveur toutes clés confondues.
#   2. PAR CLÉ  : rate_limit_max / rate_limit_window définis dans api_keys.
#                 NULL = illimité pour cette clé.
#
GLOBAL_RATE_MAX    = ENV.fetch('RATE_LIMIT_GLOBAL_MAX',    '1000').to_i   # 1000 req
GLOBAL_RATE_WINDOW = ENV.fetch('RATE_LIMIT_GLOBAL_WINDOW', '3600').to_i   # par heure

# Mutex pour éviter les race conditions sur le comptage
RATE_MUTEX = Mutex.new

# Compte les hits dans la fenêtre et insère le nouveau hit si sous la limite.
# Retourne [autorisé (bool), hits_actuels, limite, fenêtre_sec]
def check_and_record_rate_limit(scope, max_requests, window_seconds)
  return [true, 0, nil, nil] if max_requests.nil? || max_requests <= 0

  RATE_MUTEX.synchronize do
    # Nettoyer les vieilles entrées (hors fenêtre)
    DB.execute(
      "DELETE FROM rate_limit_hits WHERE scope = ? AND hit_at < datetime('now', ? || ' seconds')",
      [scope, (-window_seconds).to_s]
    )

    # Compter les hits dans la fenêtre courante
    current = DB.execute(
      "SELECT count(*) FROM rate_limit_hits WHERE scope = ? AND hit_at >= datetime('now', ? || ' seconds')",
      [scope, (-window_seconds).to_s]
    ).first[0].to_i

    allowed = current < max_requests

    # Enregistrer le hit seulement si autorisé
    if allowed
      DB.execute(
        "INSERT INTO rate_limit_hits (scope, hit_at) VALUES (?, CURRENT_TIMESTAMP)",
        [scope]
      )
    end

    [allowed, current + (allowed ? 1 : 0), max_requests, window_seconds]
  end
end

# ─────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────
helpers do

  def admin_auth!
    header = request.env['HTTP_AUTHORIZATION']
    unless header == "Bearer #{ENV['ADMIN_PASSWORD']}"
      LOGGER.warn("Auth admin échouée | IP: #{request.ip} | Header: #{header.inspect}")
      halt 401, json_response({ error: 'Non autorisé' }, 401)
    end
  end

  def api_key_auth!
    request.body.rewind
    body = JSON.parse(request.body.read) rescue {}
    request.body.rewind

    api_key = body['api_key'] || request.env['HTTP_X_API_KEY']

    unless api_key
      LOGGER.warn("Clé API absente | IP: #{request.ip}")
      halt 401, json_response({ error: 'Clé API manquante' }, 401)
    end

    @key_config = DB.get_first_row(
      'SELECT * FROM api_keys WHERE api_key = ?',
      api_key
    )

    unless @key_config
      LOGGER.warn("Clé API invalide | IP: #{request.ip} | Clé: #{api_key}")
      halt 403, json_response({ error: 'Clé API invalide' }, 403)
    end

    LOGGER.debug("Auth OK | Tenant: #{@key_config['name']}")
  end

  # Vérifie le rate limit global puis celui de la clé.
  # Doit être appelé APRÈS api_key_auth!
  def check_rate_limits!
    # 1. Rate limit global
    allowed, current, max, window = check_and_record_rate_limit(
      'global', GLOBAL_RATE_MAX, GLOBAL_RATE_WINDOW
    )

    unless allowed
      msg = "Rate limit GLOBAL atteint | #{current}/#{max} req sur #{window}s | IP: #{request.ip}"
      LOGGER.warn(msg)
      headers(
        'X-RateLimit-Scope'     => 'global',
        'X-RateLimit-Limit'     => max.to_s,
        'X-RateLimit-Remaining' => '0',
        'X-RateLimit-Window'    => window.to_s,
        'Retry-After'           => window.to_s
      )
      log_request(status: 'error', error_msg: 'Rate limit global dépassé')
      halt 429, json_response({
                                error: 'Trop de requêtes (limite globale du serveur atteinte).',
                                retry_after: window
                              }, 429)
    end

    # 2. Rate limit par clé API (si configuré)
    key_max    = @key_config['rate_limit_max']
    key_window = @key_config['rate_limit_window'] || 3600

    if key_max
      allowed, current, max, window = check_and_record_rate_limit(
        @key_config['id'], key_max, key_window
      )

      unless allowed
        msg = "Rate limit CLÉ atteint | Tenant: #{@key_config['name']} | #{current}/#{max} req sur #{window}s"
        LOGGER.warn(msg)
        headers(
          'X-RateLimit-Scope'     => 'key',
          'X-RateLimit-Limit'     => max.to_s,
          'X-RateLimit-Remaining' => '0',
          'X-RateLimit-Window'    => window.to_s,
          'Retry-After'           => window.to_s
        )
        log_request(status: 'error', error_msg: "Rate limit clé dépassé (#{current}/#{max})")
        halt 429, json_response({
                                  error: "Trop de requêtes pour cette clé API (#{max} max sur #{window}s).",
                                  retry_after: window
                                }, 429)
      end

      # Ajouter les headers informatifs si sous la limite
      headers(
        'X-RateLimit-Scope'     => 'key',
        'X-RateLimit-Limit'     => max.to_s,
        'X-RateLimit-Remaining' => [0, max - current].max.to_s,
        'X-RateLimit-Window'    => window.to_s
      )
    end
  end

  def json_response(data, status = 200)
    content_type :json
    status status
    data.to_json
  end

  def log_request(status:, error_msg: nil, recipient: nil, subject: nil)
    DB.execute(
      'INSERT INTO request_logs (id, api_key_id, tenant_name, status, error_msg, recipient, subject, ip, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [
        SecureRandom.uuid,
        @key_config&.dig('id'),
        @key_config&.dig('name'),
        status,
        error_msg,
        recipient,
        subject,
        request.ip
      ]
    )
  rescue SQLite3::Exception => e
    LOGGER.error("Impossible d'écrire le log de requête | #{e.message}")
  end

  # Extrait proprement le domaine d'une adresse email
  # Gère "Nom <email@domain.com>" et "email@domain.com"
  def extract_domain(email_str)
    return nil unless email_str
    addr = email_str.match(/<([^>]+)>/)&.captures&.first || email_str
    addr.strip.split('@').last&.downcase
  end

  # ── Vérification de l'origine HTTP ──────────────────────────────
  # Vérifie si la requête vient d'une origine autorisée pour cette clé.
  #
  # Logique :
  #   • Si la clé n'a AUCUNE origine configurée → accès libre (usage serveur-à-serveur).
  #   • Si la clé a au moins une origine → seules ces origines sont acceptées.
  #   • Les requêtes sans header Origin/Referer sont refusées si la clé a des origines.
  #
  # Normalisation : on compare l'origin sans slash final et en minuscules.
  # Support wildcards : "*.monsite.com" accepte n'importe quel sous-domaine.
  def check_origin!
    # Compter les origines configurées pour cette clé
    origins_count = DB.execute(
      'SELECT count(*) FROM allowed_origins WHERE api_key_id = ?',
      [@key_config['id']]
    ).first[0].to_i

    # Aucune restriction → on laisse passer (usage backend/serveur)
    return if origins_count == 0

    # Lire l'origine de la requête (Origin prioritaire, Referer en fallback)
    request_origin = request.env['HTTP_ORIGIN']

    # Fallback sur Referer si Origin absent (certains navigateurs/libs)
    if request_origin.nil? || request_origin.empty?
      referer = request.env['HTTP_REFERER']
      if referer && !referer.empty?
        # Extraire scheme://host(:port) depuis le Referer
        uri = URI.parse(referer) rescue nil
        request_origin = "#{uri.scheme}://#{uri.host}#{uri.port && ![80,443].include?(uri.port) ? ":#{uri.port}" : ''}" if uri
      end
    end

    # Pas d'origine du tout et clé restreinte → refus
    unless request_origin && !request_origin.empty?
      msg = "Origine absente | Tenant: #{@key_config['name']}"
      LOGGER.warn(msg)
      log_request(status: 'error', error_msg: 'Origine HTTP manquante (clé restreinte par origine)')
      halt 403, json_response({
                                error: 'Cette clé API est restreinte par origine. Ajoutez le header Origin à votre requête.',
                                code:  'ORIGIN_MISSING'
                              }, 403)
    end

    # Normaliser l'origine reçue
    normalized_request = normalize_origin(request_origin)

    # Chercher une correspondance dans la liste blanche
    allowed_origins = DB.execute(
      'SELECT origin FROM allowed_origins WHERE api_key_id = ?',
      [@key_config['id']]
    ).map { |r| r['origin'] }

    match = allowed_origins.any? { |o| origin_matches?(normalized_request, normalize_origin(o)) }

    unless match
      msg = "Origine non autorisée: #{request_origin} | Tenant: #{@key_config['name']}"
      LOGGER.warn(msg)
      log_request(status: 'error', error_msg: "Origine refusée: #{request_origin}")
      halt 403, json_response({
                                error: "L'origine '#{request_origin}' n'est pas autorisée pour cette clé API.",
                                code:  'ORIGIN_NOT_ALLOWED'
                              }, 403)
    end

    LOGGER.debug("Origine autorisée: #{request_origin} | Tenant: #{@key_config['name']}")
  end

  # Normalise une origine : minuscules, sans slash final
  def normalize_origin(origin)
    origin.to_s.strip.downcase.chomp('/')
  end

  # Vérifie si l'origine de la requête correspond à un pattern autorisé.
  # Supporte les wildcards : "https://*.monsite.com" accepte tout sous-domaine.
  def origin_matches?(request_origin, allowed_pattern)
    return true if request_origin == allowed_pattern

    # Support wildcard *.domain.com
    if allowed_pattern.include?('*')
      # Convertir le pattern glob en regex
      regex_str = Regexp.escape(allowed_pattern).gsub('\*', '[^.]+')
      return request_origin.match?(/\A#{regex_str}\z/)
    end

    false
  end
end

# ─────────────────────────────────────────
#  Middleware logging HTTP
# ─────────────────────────────────────────
before do
  LOGGER.info("→ #{request.request_method} #{request.path_info} | IP: #{request.ip}")
end

after do
  LOGGER.info("← #{request.request_method} #{request.path_info} | #{response.status}")
end

# ─────────────────────────────────────────
#  POST /api/send
# ─────────────────────────────────────────
post '/api/send' do
  api_key_auth!
  check_origin!
  check_rate_limits!

  request.body.rewind
  raw = request.body.read

  begin
    payload = JSON.parse(raw)
  rescue JSON::ParserError => e
    LOGGER.error("JSON invalide | #{e.message}")
    log_request(status: 'error', error_msg: "JSON invalide: #{e.message}")
    halt 400, json_response({ error: 'Corps JSON invalide' }, 400)
  end

  to      = payload['to']
  subject = payload['subject']
  text    = payload['text']
  html    = payload['html']
  from    = payload['from']

  unless to && subject
    msg = "Champs manquants: to=#{to.inspect} subject=#{subject.inspect}"
    LOGGER.warn(msg)
    log_request(status: 'error', error_msg: msg, recipient: to, subject: subject)
    halt 400, json_response({ error: 'Destinataire et sujet requis' }, 400)
  end

  # Résoudre l'adresse expéditrice finale
  from_email      = from || @key_config['smtp_from_email']
  from_domain     = extract_domain(from_email)
  config_domain   = extract_domain(@key_config['smtp_from_email'])
  is_own_domain   = (from_domain == config_domain)

  unless is_own_domain
    # Chercher ce domaine dans la liste blanche de la clé
    allowed = DB.get_first_row(
      'SELECT * FROM allowed_domains WHERE api_key_id = ? AND LOWER(domain) = LOWER(?)',
      [@key_config['id'], from_domain]
    )

    unless allowed
      msg = "Domaine non autorisé: #{from_domain} (domaine propre: #{config_domain})"
      LOGGER.warn("#{msg} | Tenant: #{@key_config['name']}")
      log_request(status: 'error', error_msg: msg, recipient: to, subject: subject)
      halt 403, json_response({
                                error: "Le domaine expéditeur '#{from_domain}' n'est pas autorisé pour cette clé.",
                                allowed_domain: config_domain
                              }, 403)
    end
  end

  LOGGER.info("Envoi | #{from_email} → #{to} | \"#{subject}\" | Tenant: #{@key_config['name']}")

  begin
    smtp_from_name        = @key_config['smtp_from_name']
    smtp_from_email_cfg   = @key_config['smtp_from_email']
    smtp_host             = @key_config['smtp_host']
    smtp_port             = @key_config['smtp_port']
    smtp_user             = @key_config['smtp_user']
    smtp_pass             = @key_config['smtp_pass']

    # Construire l'expéditeur : si from fourni, utiliser tel quel ;
    # sinon reconstruire avec le nom configuré
    display_from = if from && from != smtp_from_email_cfg
                     from  # L'appelant a fourni un from complet ou une adresse d'un domaine autorisé
                   else
                     "#{smtp_from_name} <#{smtp_from_email_cfg}>"
                   end

    message = Mail.new do
      from    display_from
      to      to
      subject subject
      text_part { body text } if text
      html_part { content_type 'text/html; charset=UTF-8'; body html } if html
    end

    message.delivery_method :smtp, {
      address:              smtp_host,
      port:                 smtp_port,
      user_name:            smtp_user,
      password:             smtp_pass,
      authentication:       :plain,
      enable_starttls_auto: true
    }

    message.deliver!
    LOGGER.info("✓ Envoyé | Message-ID: #{message.message_id}")
    log_request(status: 'success', recipient: to, subject: subject)
    json_response({ success: true, message_id: message.message_id })

  rescue Net::SMTPAuthenticationError => e
    LOGGER.error("SMTP auth échouée | #{@key_config['smtp_user']}@#{@key_config['smtp_host']} | #{e.message}")
    log_request(status: 'error', error_msg: "SMTP auth: #{e.message}", recipient: to, subject: subject)
    halt 500, json_response({ error: "Échec SMTP: identifiants invalides. (#{e.message})" }, 500)

  rescue Net::SMTPFatalError => e
    LOGGER.error("SMTP erreur fatale | #{@key_config['smtp_host']}:#{@key_config['smtp_port']} | #{e.message}")
    LOGGER.error(e.backtrace.first(3).join("\n"))
    log_request(status: 'error', error_msg: "SMTP fatal: #{e.message}", recipient: to, subject: subject)
    halt 500, json_response({ error: "Erreur SMTP: #{e.message}" }, 500)

  rescue Net::SMTPServerBusy => e
    LOGGER.warn("SMTP surchargé | #{e.message}")
    log_request(status: 'error', error_msg: "SMTP busy: #{e.message}", recipient: to, subject: subject)
    halt 503, json_response({ error: 'Serveur SMTP temporairement indisponible.' }, 503)

  rescue Net::OpenTimeout, Net::ReadTimeout => e
    LOGGER.error("SMTP timeout | #{@key_config['smtp_host']}:#{@key_config['smtp_port']} | #{e.message}")
    log_request(status: 'error', error_msg: "Timeout: #{e.message}", recipient: to, subject: subject)
    halt 504, json_response({ error: 'Timeout: impossible de joindre le serveur SMTP.' }, 504)

  rescue => e
    LOGGER.fatal("Erreur inattendue | #{e.class}: #{e.message}")
    LOGGER.fatal("Backtrace:\n#{e.backtrace.first(8).join("\n")}")
    log_request(status: 'error', error_msg: "#{e.class}: #{e.message}", recipient: to, subject: subject)
    halt 500, json_response({ error: "Erreur inattendue: #{e.message}" }, 500)
  end
end

# ─────────────────────────────────────────
#  Routes Admin — Clés
# ─────────────────────────────────────────
get '/api/admin/config' do
  admin_auth!
  keys    = DB.execute('SELECT id, name, api_key, smtp_from_email, smtp_from_name, rate_limit_max, rate_limit_window, created_at FROM api_keys')
  domains = DB.execute('SELECT id, api_key_id, domain FROM allowed_domains')
  origins = DB.execute('SELECT id, api_key_id, origin, label FROM allowed_origins ORDER BY api_key_id')
  LOGGER.info("Config admin lue | #{keys.length} clé(s) | #{origins.length} origine(s)")
  json_response({ keys: keys, domains: domains, origins: origins })
end

get '/api/admin/keys/:id' do
  admin_auth!
  key = DB.get_first_row('SELECT * FROM api_keys WHERE id = ?', params[:id])
  halt 404, json_response({ error: 'Clé introuvable' }, 404) unless key
  json_response(key)
end

post '/api/admin/keys' do
  admin_auth!
  request.body.rewind
  data    = JSON.parse(request.body.read)
  id      = SecureRandom.uuid
  api_key = "pb_formto_#{SecureRandom.hex(16)}"

  # rate_limit_max: nil = désactivé, entier = activé
  rate_max    = data['rate_limit_max'].to_s.empty? ? nil : data['rate_limit_max'].to_i
  rate_window = (data['rate_limit_window'] || 3600).to_i

  begin
    DB.execute(
      'INSERT INTO api_keys (id, name, api_key, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from_email, smtp_from_name, rate_limit_max, rate_limit_window)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, data['name'], api_key, data['smtp_host'], data['smtp_port'],
       data['smtp_user'], data['smtp_pass'], data['smtp_from_email'], data['smtp_from_name'],
       rate_max, rate_window]
    )
    LOGGER.info("Clé créée | #{data['name']} | ID: #{id} | Rate: #{rate_max || 'illimité'}/#{rate_window}s")
    json_response({ success: true, api_key: api_key })
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur création clé | #{e.message}")
    halt 500, json_response({ error: "DB: #{e.message}" }, 500)
  end
end

put '/api/admin/keys/:id' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read)

  rate_max    = data['rate_limit_max'].to_s.empty? ? nil : data['rate_limit_max'].to_i
  rate_window = (data['rate_limit_window'] || 3600).to_i

  begin
    DB.execute(
      'UPDATE api_keys SET name=?, smtp_host=?, smtp_port=?, smtp_user=?, smtp_pass=?, smtp_from_email=?, smtp_from_name=?, rate_limit_max=?, rate_limit_window=? WHERE id=?',
      [data['name'], data['smtp_host'], data['smtp_port'], data['smtp_user'],
       data['smtp_pass'], data['smtp_from_email'], data['smtp_from_name'],
       rate_max, rate_window, params[:id]]
    )
    LOGGER.info("Clé mise à jour | ID: #{params[:id]} | Rate: #{rate_max || 'illimité'}/#{rate_window}s")
    json_response({ success: true })
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur MAJ clé | #{e.message}")
    halt 500, json_response({ error: "DB: #{e.message}" }, 500)
  end
end

delete '/api/admin/keys/:id' do
  admin_auth!
  DB.execute('DELETE FROM api_keys WHERE id = ?', params[:id])
  # Nettoyer aussi les hits de rate limit pour cette clé
  DB.execute('DELETE FROM rate_limit_hits WHERE scope = ?', params[:id])
  LOGGER.warn("Clé supprimée | ID: #{params[:id]}")
  json_response({ success: true })
end

# ─────────────────────────────────────────
#  Routes Admin — Origines HTTP autorisées
# ─────────────────────────────────────────
get '/api/admin/origins' do
  admin_auth!
  origins = DB.execute('SELECT * FROM allowed_origins ORDER BY api_key_id, label')
  json_response({ origins: origins })
end

post '/api/admin/origins' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read)
  id   = SecureRandom.uuid

  raw_origin = data['origin'].to_s.strip
  # Normaliser : forcer scheme si absent, supprimer slash final
  origin = raw_origin.match?(/\Ahttps?:\/\//) ? raw_origin.chomp('/') : "https://#{raw_origin.chomp('/')}"
  label  = data['label'].to_s.strip

  begin
    DB.execute(
      'INSERT INTO allowed_origins (id, api_key_id, origin, label) VALUES (?, ?, ?, ?)',
      [id, data['api_key_id'], origin, label.empty? ? nil : label]
    )
    LOGGER.info("Origine ajoutée | #{origin} → clé #{data['api_key_id']}")
    json_response({ success: true, id: id, origin: origin })
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur ajout origine | #{e.message}")
    halt 500, json_response({ error: "DB: #{e.message}" }, 500)
  end
end

delete '/api/admin/origins/:id' do
  admin_auth!
  DB.execute('DELETE FROM allowed_origins WHERE id = ?', params[:id])
  LOGGER.warn("Origine supprimée | ID: #{params[:id]}")
  json_response({ success: true })
end

# ─────────────────────────────────────────
#  Routes Admin — Domaines expéditeur email
post '/api/admin/domains' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read)
  id   = SecureRandom.uuid

  # Normaliser le domaine (minuscules, sans espaces ni http://)
  domain = data['domain'].to_s.strip.downcase.gsub(%r{^https?://}, '').split('/').first

  begin
    DB.execute('INSERT INTO allowed_domains (id, api_key_id, domain) VALUES (?, ?, ?)',
               [id, data['api_key_id'], domain])
    LOGGER.info("Domaine ajouté | #{domain}")
    json_response({ success: true })
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur ajout domaine | #{e.message}")
    halt 500, json_response({ error: "DB: #{e.message}" }, 500)
  end
end

delete '/api/admin/domains/:id' do
  admin_auth!
  DB.execute('DELETE FROM allowed_domains WHERE id = ?', params[:id])
  LOGGER.warn("Domaine supprimé | ID: #{params[:id]}")
  json_response({ success: true })
end

post '/api/admin/test-smtp' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read)

  begin
    smtp_host  = data['smtp_host']
    smtp_port  = data['smtp_port'].to_i
    smtp_user  = data['smtp_user']
    smtp_pass  = data['smtp_pass']
    from_email = data['smtp_from_email']
    from_name  = data['smtp_from_name']

    message = Mail.new do
      from    "#{from_name} <#{from_email}>"
      to      from_email
      subject 'FormTo — Test SMTP'
      text_part { body 'Si vous recevez ce message, votre configuration SMTP est correcte.' }
    end

    message.delivery_method :smtp, {
      address:              smtp_host,
      port:                 smtp_port,
      user_name:            smtp_user,
      password:             smtp_pass,
      authentication:       :plain,
      enable_starttls_auto: true
    }

    message.deliver!
    LOGGER.info("Test SMTP OK | #{smtp_user}@#{smtp_host}")
    json_response({ success: true })

  rescue => e
    LOGGER.warn("Test SMTP échoué | #{e.message}")
    halt 400, json_response({ success: false, error: e.message }, 400)
  end
end

# ─────────────────────────────────────────
#  Rate Limit — Stats par clé
# ─────────────────────────────────────────
get '/api/admin/rate-limit-stats' do
  admin_auth!

  global_count = DB.execute(
    "SELECT count(*) FROM rate_limit_hits WHERE scope = 'global' AND hit_at >= datetime('now', '-' || ? || ' seconds')",
    [GLOBAL_RATE_WINDOW]
  ).first[0].to_i

  keys_stats = DB.execute(
    "SELECT ak.id, ak.name, ak.rate_limit_max, ak.rate_limit_window,
            COUNT(rl.id) as current_hits
     FROM api_keys ak
     LEFT JOIN rate_limit_hits rl
       ON rl.scope = ak.id
       AND rl.hit_at >= datetime('now', '-' || ak.rate_limit_window || ' seconds')
     GROUP BY ak.id"
  )

  json_response({
                  global: {
                    current:  global_count,
                    max:      GLOBAL_RATE_MAX,
                    window:   GLOBAL_RATE_WINDOW,
                    remaining: [0, GLOBAL_RATE_MAX - global_count].max
                  },
                  keys: keys_stats
                })
end

# ─────────────────────────────────────────
#  Check Update
# ─────────────────────────────────────────
CURRENT_VERSION = 'v1.2'.freeze
DOCKER_IMAGE    = 'yidirk/formto'.freeze
UPDATE_CACHE_FILE = '/tmp/formto_update_cache.json'.freeze

def check_update_once
  if File.exist?(UPDATE_CACHE_FILE)
    age = Time.now - File.mtime(UPDATE_CACHE_FILE)
    return JSON.parse(File.read(UPDATE_CACHE_FILE), symbolize_names: true) if age < 86400
  end

  require 'net/http'
  uri = URI("https://hub.docker.com/v2/repositories/#{DOCKER_IMAGE}/tags?page_size=10&ordering=last_updated")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.read_timeout = 8
  http.open_timeout = 5
  req = Net::HTTP::Get.new(uri)
  req['Accept']     = 'application/json'
  req['User-Agent'] = "formto/#{CURRENT_VERSION}"
  response = http.request(req)
  return nil unless response.code == '200'

  data = JSON.parse(response.body)
  tags = data['results']&.map { |t| t['name'] } || []
  latest = tags.select { |t| t.match?(/\Av?\d+\.\d+/) }
               .sort_by { |t| t.gsub(/\Av/, '').split('.').map(&:to_i) }
               .last

  result = {
    update_available: latest && (latest.gsub(/\Av/, '').split('.').map(&:to_i) <=> CURRENT_VERSION.gsub(/\Av/, '').split('.').map(&:to_i)) == 1,
    current_version:  CURRENT_VERSION,
    latest_version:   latest
  }

  File.write(UPDATE_CACHE_FILE, result.to_json)
  result
rescue
  nil
end

get '/api/admin/check-update' do
  admin_auth!
  result = check_update_once
  return json_response({ update_available: false, error: 'Impossible de vérifier', current_version: CURRENT_VERSION }, 503) unless result
  json_response(result)
end
# ─────────────────────────────────────────
#  Routes Admin — Stats & Logs
# ─────────────────────────────────────────
get '/api/admin/stats' do
  admin_auth!

  total   = DB.execute('SELECT count(*) FROM request_logs').first[0]
  success = DB.execute("SELECT count(*) FROM request_logs WHERE status = 'success'").first[0]
  errors  = DB.execute("SELECT count(*) FROM request_logs WHERE status = 'error'").first[0]

  hourly = DB.execute(<<-SQL)
    SELECT
      strftime('%H:00', created_at) as hour,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
      SUM(CASE WHEN status = 'error'   THEN 1 ELSE 0 END) as error
    FROM request_logs
    WHERE created_at >= datetime('now', '-24 hours')
    GROUP BY hour
    ORDER BY hour
  SQL

  daily = DB.execute(<<-SQL)
    SELECT
      strftime('%Y-%m-%d', created_at) as day,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
      SUM(CASE WHEN status = 'error'   THEN 1 ELSE 0 END) as error
    FROM request_logs
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY day
    ORDER BY day
  SQL

  by_tenant = DB.execute(<<-SQL)
    SELECT
      tenant_name,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
      SUM(CASE WHEN status = 'error'   THEN 1 ELSE 0 END) as error
    FROM request_logs
    GROUP BY tenant_name
    ORDER BY (success + error) DESC
  SQL

  json_response({
                  total:     total,
                  success:   success,
                  errors:    errors,
                  rate:      total > 0 ? ((success.to_f / total) * 100).round(1) : 0,
                  hourly:    hourly,
                  daily:     daily,
                  by_tenant: by_tenant
                })
end

get '/api/admin/logs' do
  admin_auth!
  limit  = (params[:limit]  || 50).to_i.clamp(1, 200)
  offset = (params[:offset] || 0).to_i
  status = params[:status]

  if status && !status.empty?
    logs  = DB.execute(
      "SELECT * FROM request_logs WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
      [status, limit, offset]
    )
    total = DB.execute("SELECT count(*) FROM request_logs WHERE status = ?", [status]).first[0]
  else
    logs  = DB.execute(
      "SELECT * FROM request_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
      [limit, offset]
    )
    total = DB.execute("SELECT count(*) FROM request_logs").first[0]
  end

  json_response({ logs: logs, total: total, limit: limit, offset: offset })
end

# ─────────────────────────────────────────
#  UI
# ─────────────────────────────────────────
get '/' do
  send_file File.join(settings.public_folder, 'index.html')
end