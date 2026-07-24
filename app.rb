require 'sinatra'
require 'sqlite3'
require 'mail'
require 'json'
require 'securerandom'
require 'fileutils'
require 'dotenv/load' if ENV['RACK_ENV'] != 'production'
require 'rack/cors'
require 'rack/utils'
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
# NB: '*' reste correct ici car /api/send est protégé par clé API + origine,
# et les routes /api/admin/* nécessitent le mot de passe admin en header
# Authorization (un site tiers ne peut pas le connaître, donc CORS large
# sur ces routes n'expose rien de sensible).
use Rack::Cors do
  allow do
    origins '*'
    resource '*', headers: :any, methods: [:get, :post, :put, :delete, :options]
  end
end

# ─────────────────────────────────────────
#  Limite de taille du corps de requête (anti-abus / anti-DoS basique)
# ─────────────────────────────────────────
MAX_BODY_BYTES = 200_000 # 200 Ko, largement suffisant pour un formulaire de contact

before do
  cl = request.content_length.to_i
  if cl > MAX_BODY_BYTES
    LOGGER.warn("Corps trop volumineux (#{cl} octets) | IP: #{request.ip} | #{request.path_info}")
    halt 413, { error: 'Corps de requête trop volumineux.' }.to_json
  end
end

# ─────────────────────────────────────────
#  Headers de sécurité de base sur toutes les réponses
# ─────────────────────────────────────────
after do
  headers['X-Content-Type-Options'] = 'nosniff'
  headers['X-Frame-Options']        = 'DENY'
  headers['Referrer-Policy']        = 'no-referrer'
end

# ─────────────────────────────────────────
#  Base de données SQLite
# ─────────────────────────────────────────
# IMPORTANT: le fichier data.db vit dans DATA_DIR, PAS dans le dossier
# de l'application. Quand vous mettez à jour l'image (nouveau code),
# le contenu de /app est remplacé — mais si DATA_DIR pointe vers un
# volume monté (ex: ./data:/app/data), la base survit à la mise à jour.
# Par défaut DATA_DIR=/app/data ; à monter en volume dans docker-compose.
DATA_DIR = ENV.fetch('DATA_DIR', File.join(File.dirname(__FILE__), 'data'))
FileUtils.mkdir_p(DATA_DIR) unless Dir.exist?(DATA_DIR)
DB_PATH = File.join(DATA_DIR, 'data.db')

# Migration automatique : les versions précédentes stockaient data.db
# directement dans le dossier de l'app (non persistant entre mises à
# jour). Si on trouve une ancienne base à cet emplacement et qu'aucune
# base n'existe encore dans DATA_DIR, on la déplace une seule fois.
OLD_DB_PATH = File.join(File.dirname(__FILE__), 'data.db')
if File.exist?(OLD_DB_PATH) && !File.exist?(DB_PATH)
  FileUtils.mv(OLD_DB_PATH, DB_PATH)
  puts "[migration] Ancienne base trouvée en #{OLD_DB_PATH} → déplacée vers #{DB_PATH}"
end

DB = SQLite3::Database.new(DB_PATH)
DB.results_as_hash = true

# Activer les clés étrangères (nécessaire pour ON DELETE CASCADE)
DB.execute('PRAGMA foreign_keys = ON')
DB.execute('PRAGMA journal_mode = WAL')

DB.execute_batch <<-SQL
  CREATE TABLE IF NOT EXISTS api_keys (
    id                  TEXT PRIMARY KEY,
    name                TEXT,
    api_key             TEXT UNIQUE,
    smtp_host           TEXT,
    smtp_port           INTEGER,
    smtp_user           TEXT,
    smtp_pass           TEXT,
    smtp_from_email     TEXT,
    smtp_from_name      TEXT,
    -- Adresse qui RECOIT les mails envoyés via cette clé.
    -- Configurée UNIQUEMENT depuis le dashboard admin : le formulaire
    -- client ne peut jamais choisir le destinataire (anti relai ouvert).
    notification_email  TEXT,
    rate_limit_max       INTEGER DEFAULT NULL,
    rate_limit_window    INTEGER DEFAULT 3600,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS allowed_origins (
    id         TEXT PRIMARY KEY,
    api_key_id TEXT,
    origin     TEXT NOT NULL,
    label      TEXT,
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
  );

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

  CREATE TABLE IF NOT EXISTS rate_limit_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,
    hit_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_rate_hits_scope_time
    ON rate_limit_hits(scope, hit_at);

  CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    id                 TEXT PRIMARY KEY,
    api_key_id         TEXT NOT NULL,
    email              TEXT NOT NULL,
    ip                 TEXT,
    unsubscribe_token  TEXT,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(api_key_id, email),
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_newsletter_key
    ON newsletter_subscribers(api_key_id);

  CREATE TABLE IF NOT EXISTS newsletter_campaigns (
    id           TEXT PRIMARY KEY,
    api_key_id   TEXT NOT NULL,
    subject      TEXT NOT NULL,
    html         TEXT,
    text         TEXT,
    status       TEXT DEFAULT 'sent',
    sent_count   INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_campaigns_key
    ON newsletter_campaigns(api_key_id);
SQL

# Migrations idempotentes
begin
  DB.execute('ALTER TABLE api_keys ADD COLUMN rate_limit_max INTEGER DEFAULT NULL')
rescue SQLite3::Exception
end
begin
  DB.execute('ALTER TABLE api_keys ADD COLUMN rate_limit_window INTEGER DEFAULT 3600')
rescue SQLite3::Exception
end
begin
  DB.execute('ALTER TABLE api_keys ADD COLUMN notification_email TEXT')
rescue SQLite3::Exception
end
begin
  DB.execute('ALTER TABLE newsletter_subscribers ADD COLUMN unsubscribe_token TEXT')
rescue SQLite3::Exception
end

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
GLOBAL_RATE_MAX    = ENV.fetch('RATE_LIMIT_GLOBAL_MAX',    '1000').to_i
GLOBAL_RATE_WINDOW = ENV.fetch('RATE_LIMIT_GLOBAL_WINDOW', '3600').to_i

RATE_MUTEX = Mutex.new

def check_and_record_rate_limit(scope, max_requests, window_seconds)
  return [true, 0, nil, nil] if max_requests.nil? || max_requests <= 0

  RATE_MUTEX.synchronize do
    DB.execute(
      "DELETE FROM rate_limit_hits WHERE scope = ? AND hit_at < datetime('now', ? || ' seconds')",
      [scope, (-window_seconds).to_s]
    )

    current = DB.execute(
      "SELECT count(*) FROM rate_limit_hits WHERE scope = ? AND hit_at >= datetime('now', ? || ' seconds')",
      [scope, (-window_seconds).to_s]
    ).first[0].to_i

    allowed = current < max_requests

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

# Format email simple mais strict (une seule adresse, pas de CR/LF, pas de virgule)
EMAIL_REGEX = /\A[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\z/

helpers do

  def valid_email?(email)
    email.is_a?(String) && !email.include?("\n") && !email.include?("\r") &&
      email.match?(EMAIL_REGEX)
  end

  # Empêche l'injection d'en-têtes SMTP (CRLF injection) même si la gem
  # `mail` encode déjà proprement les champs — défense en profondeur.
  def sanitize_header_value(str, max_len: 500)
    return nil if str.nil?
    str.to_s.gsub(/[\r\n]+/, ' ').strip[0, max_len]
  end

  # Protection anti brute-force sur le mot de passe admin : au-delà de
  # ADMIN_LOGIN_MAX_FAILS échecs pour une IP donnée sur la fenêtre, les
  # tentatives suivantes sont bloquées (429), même avec le bon mot de
  # passe, le temps que la fenêtre expire.
  ADMIN_LOGIN_MAX_FAILS   = ENV.fetch('ADMIN_LOGIN_MAX_FAILS', '10').to_i
  ADMIN_LOGIN_FAIL_WINDOW = ENV.fetch('ADMIN_LOGIN_FAIL_WINDOW', '300').to_i

  def admin_login_blocked?(ip)
    scope = "admin_fail:#{ip}"
    DB.execute(
      "DELETE FROM rate_limit_hits WHERE scope = ? AND hit_at < datetime('now', ? || ' seconds')",
      [scope, (-ADMIN_LOGIN_FAIL_WINDOW).to_s]
    )
    count = DB.execute(
      "SELECT count(*) FROM rate_limit_hits WHERE scope = ? AND hit_at >= datetime('now', ? || ' seconds')",
      [scope, (-ADMIN_LOGIN_FAIL_WINDOW).to_s]
    ).first[0].to_i
    count >= ADMIN_LOGIN_MAX_FAILS
  end

  def record_admin_login_failure(ip)
    DB.execute(
      "INSERT INTO rate_limit_hits (scope, hit_at) VALUES (?, CURRENT_TIMESTAMP)",
      ["admin_fail:#{ip}"]
    )
  end

  def admin_auth!
    ip = request.ip

    if admin_login_blocked?(ip)
      LOGGER.warn("Admin bloqué (trop de tentatives échouées) | IP: #{ip}")
      halt 429, json_response({ error: "Trop de tentatives échouées. Réessayez dans #{ADMIN_LOGIN_FAIL_WINDOW / 60} minutes." }, 429)
    end

    header   = request.env['HTTP_AUTHORIZATION']
    expected = "Bearer #{ENV['ADMIN_PASSWORD']}"

    unless header && ENV['ADMIN_PASSWORD'] && header.bytesize == expected.bytesize && Rack::Utils.secure_compare(header, expected)
      record_admin_login_failure(ip)
      LOGGER.warn("Auth admin échouée | IP: #{ip}")
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
      LOGGER.warn("Clé API invalide | IP: #{request.ip}")
      halt 403, json_response({ error: 'Clé API invalide' }, 403)
    end

    LOGGER.debug("Auth OK | Tenant: #{@key_config['name']}")
  end

  def check_rate_limits!
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

  def extract_domain(email_str)
    return nil unless email_str
    addr = email_str.match(/<([^>]+)>/)&.captures&.first || email_str
    addr.strip.split('@').last&.downcase
  end

  def check_origin!
    origins_count = DB.execute(
      'SELECT count(*) FROM allowed_origins WHERE api_key_id = ?',
      [@key_config['id']]
    ).first[0].to_i

    return if origins_count == 0

    request_origin = request.env['HTTP_ORIGIN']

    if request_origin.nil? || request_origin.empty?
      referer = request.env['HTTP_REFERER']
      if referer && !referer.empty?
        uri = URI.parse(referer) rescue nil
        request_origin = "#{uri.scheme}://#{uri.host}#{uri.port && ![80,443].include?(uri.port) ? ":#{uri.port}" : ''}" if uri
      end
    end

    unless request_origin && !request_origin.empty?
      msg = "Origine absente | Tenant: #{@key_config['name']}"
      LOGGER.warn(msg)
      log_request(status: 'error', error_msg: 'Origine HTTP manquante (clé restreinte par origine)')
      halt 403, json_response({
                                error: 'Cette clé API est restreinte par origine. Ajoutez le header Origin à votre requête.',
                                code:  'ORIGIN_MISSING'
                              }, 403)
    end

    normalized_request = normalize_origin(request_origin)

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

  def normalize_origin(origin)
    origin.to_s.strip.downcase.chomp('/')
  end

  def origin_matches?(request_origin, allowed_pattern)
    return true if request_origin == allowed_pattern

    if allowed_pattern.include?('*')
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

  # ── Destinataire : JAMAIS fourni par le client. ──────────────────
  # Il est fixé une fois pour toutes dans le dashboard admin, par clé API.
  # Ainsi, même si la clé fuite ou que l'origine est mal configurée,
  # personne ne peut détourner FormTo pour spammer un tiers.
  to = @key_config['notification_email']

  unless valid_email?(to)
    msg = "Aucun email destinataire valide configuré pour cette clé"
    LOGGER.error("#{msg} | Tenant: #{@key_config['name']}")
    log_request(status: 'error', error_msg: msg)
    halt 500, json_response({
                              error: "Cette clé API n'a pas d'email destinataire configuré. Configurez-le dans le dashboard admin.",
                              code:  'NOTIFICATION_EMAIL_MISSING'
                            }, 500)
  end

  subject  = sanitize_header_value(payload['subject'], max_len: 250)
  text     = payload['text'].to_s[0, 200_000] if payload['text']
  html     = payload['html'].to_s[0, 200_000] if payload['html']
  from_raw = payload['from']

  if subject.nil? || subject.empty?
    msg = "Champ manquant: subject"
    LOGGER.warn(msg)
    log_request(status: 'error', error_msg: msg, recipient: to)
    halt 400, json_response({ error: 'Sujet requis' }, 400)
  end

  unless text || html
    msg = "Aucun contenu (text ou html) fourni"
    LOGGER.warn(msg)
    log_request(status: 'error', error_msg: msg, recipient: to, subject: subject)
    halt 400, json_response({ error: 'Contenu du message requis (text ou html)' }, 400)
  end

  # Résoudre l'adresse expéditrice finale
  from_email      = from_raw && valid_email?(sanitize_header_value(from_raw)) ? sanitize_header_value(from_raw) : @key_config['smtp_from_email']
  from_domain     = extract_domain(from_email)
  config_domain   = extract_domain(@key_config['smtp_from_email'])
  is_own_domain   = (from_domain == config_domain)

  unless is_own_domain
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

  # reply_to est optionnel et sans risque : il ne change jamais le
  # destinataire réel du mail, seulement l'adresse pré-remplie en cas
  # de réponse (pratique pour un formulaire de contact).
  reply_to = payload['reply_to']
  reply_to = sanitize_header_value(reply_to)
  reply_to = nil unless reply_to && valid_email?(reply_to)

  LOGGER.info("Envoi | #{from_email} → #{to} | \"#{subject}\" | Tenant: #{@key_config['name']}")

  begin
    smtp_from_name        = @key_config['smtp_from_name']
    smtp_from_email_cfg    = @key_config['smtp_from_email']
    smtp_host              = @key_config['smtp_host']
    smtp_port               = @key_config['smtp_port']
    smtp_user               = @key_config['smtp_user']
    smtp_pass                = @key_config['smtp_pass']

    display_from = if from_raw && from_email != smtp_from_email_cfg
                     from_email
                   else
                     "#{sanitize_header_value(smtp_from_name)} <#{smtp_from_email_cfg}>"
                   end

    message = Mail.new do
      from     display_from
      to       to
      subject  subject
      reply_to reply_to if reply_to
      text_part { body text } if text
      html_part { content_type 'text/html; charset=UTF-8'; body html } if html
    end

    message.delivery_method :smtp, {
      address:              smtp_host,
      port:                 smtp_port,
      user_name:            smtp_user,
      password:             smtp_pass,
      authentication:       :plain,
      enable_starttls_auto: true,
      open_timeout:         10,
      read_timeout:         20
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
#  POST /api/subscribe — Inscription newsletter
# ─────────────────────────────────────────
# Réutilise les mêmes protections que /api/send : clé API valide,
# origine autorisée (si configurée) et rate limiting. L'email n'est
# jamais renvoyé publiquement et les doublons ne sont pas signalés
# (pour éviter l'énumération d'adresses déjà inscrites).
post '/api/subscribe' do
  api_key_auth!
  check_origin!
  check_rate_limits!

  request.body.rewind
  payload = JSON.parse(request.body.read) rescue {}

  email = payload['email'].to_s.strip.downcase

  unless valid_email?(email)
    log_request(status: 'error', error_msg: 'Email newsletter invalide', subject: '[newsletter]')
    halt 400, json_response({ error: 'Adresse email invalide.' }, 400)
  end

  begin
    DB.execute(
      'INSERT INTO newsletter_subscribers (id, api_key_id, email, ip, unsubscribe_token) VALUES (?, ?, ?, ?, ?)',
      [SecureRandom.uuid, @key_config['id'], email, request.ip, SecureRandom.hex(20)]
    )
    LOGGER.info("Newsletter: nouvel abonné | Tenant: #{@key_config['name']}")
    log_request(status: 'success', recipient: email, subject: '[newsletter] inscription')
  rescue SQLite3::ConstraintException
    # Déjà inscrit : on répond quand même succès, sans le préciser.
    LOGGER.debug("Newsletter: email déjà inscrit | Tenant: #{@key_config['name']}")
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur inscription newsletter | #{e.message}")
    log_request(status: 'error', error_msg: "DB: #{e.message}", subject: '[newsletter]')
    halt 500, json_response({ error: 'Erreur serveur, réessayez plus tard.' }, 500)
  end

  json_response({ success: true, message: 'Inscription confirmée.' })
end

# ─────────────────────────────────────────
#  GET /api/unsubscribe/:token — Désinscription newsletter
# ─────────────────────────────────────────
# Route publique, sans authentification : le token à lui seul identifie
# l'abonné (assez long et aléatoire pour ne pas être devinable). Utilisée
# depuis le lien "se désinscrire" présent dans chaque campagne envoyée.
get '/api/unsubscribe/:token' do
  sub = DB.get_first_row(
    'SELECT * FROM newsletter_subscribers WHERE unsubscribe_token = ?',
    [params[:token]]
  )

  content_type 'text/html; charset=utf-8'

  unless sub
    halt 404, <<~HTML
      <!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px">
      <h2>Lien invalide</h2><p>Ce lien de désinscription n'est plus valide.</p></body></html>
    HTML
  end

  DB.execute('DELETE FROM newsletter_subscribers WHERE id = ?', [sub['id']])
  LOGGER.info("Newsletter: désinscription | #{sub['email']}")

  <<~HTML
    <!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px">
    <h2>✅ Désinscription confirmée</h2><p>Vous ne recevrez plus d'emails de cette liste.</p></body></html>
  HTML
end

# ─────────────────────────────────────────
#  Routes Admin — Clés
# ─────────────────────────────────────────
get '/api/admin/config' do
  admin_auth!
  keys = DB.execute(<<-SQL)
    SELECT ak.id, ak.name, ak.api_key, ak.smtp_from_email, ak.smtp_from_name,
           ak.notification_email, ak.rate_limit_max, ak.rate_limit_window, ak.created_at,
           (SELECT COUNT(*) FROM newsletter_subscribers ns WHERE ns.api_key_id = ak.id) AS newsletter_count
    FROM api_keys ak
  SQL
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

  rate_max    = data['rate_limit_max'].to_s.empty? ? nil : data['rate_limit_max'].to_i
  rate_window = (data['rate_limit_window'] || 3600).to_i

  notification_email = data['notification_email'].to_s.strip
  unless valid_email?(notification_email)
    halt 400, json_response({ error: "Email destinataire invalide ou manquant." }, 400)
  end

  begin
    DB.execute(
      'INSERT INTO api_keys (id, name, api_key, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from_email, smtp_from_name, notification_email, rate_limit_max, rate_limit_window)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, data['name'], api_key, data['smtp_host'], data['smtp_port'],
       data['smtp_user'], data['smtp_pass'], data['smtp_from_email'], data['smtp_from_name'],
       notification_email, rate_max, rate_window]
    )
    LOGGER.info("Clé créée | #{data['name']} | ID: #{id} | Destinataire: #{notification_email}")
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

  notification_email = data['notification_email'].to_s.strip
  unless valid_email?(notification_email)
    halt 400, json_response({ error: "Email destinataire invalide ou manquant." }, 400)
  end

  begin
    DB.execute(
      'UPDATE api_keys SET name=?, smtp_host=?, smtp_port=?, smtp_user=?, smtp_pass=?, smtp_from_email=?, smtp_from_name=?, notification_email=?, rate_limit_max=?, rate_limit_window=? WHERE id=?',
      [data['name'], data['smtp_host'], data['smtp_port'], data['smtp_user'],
       data['smtp_pass'], data['smtp_from_email'], data['smtp_from_name'],
       notification_email, rate_max, rate_window, params[:id]]
    )
    LOGGER.info("Clé mise à jour | ID: #{params[:id]} | Destinataire: #{notification_email}")
    json_response({ success: true })
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur MAJ clé | #{e.message}")
    halt 500, json_response({ error: "DB: #{e.message}" }, 500)
  end
end

delete '/api/admin/keys/:id' do
  admin_auth!
  DB.execute('DELETE FROM api_keys WHERE id = ?', params[:id])
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
#  Routes Admin — Newsletter
# ─────────────────────────────────────────
get '/api/admin/newsletter/:key_id' do
  admin_auth!
  subs = DB.execute(
    'SELECT * FROM newsletter_subscribers WHERE api_key_id = ? ORDER BY created_at DESC',
    params[:key_id]
  )
  json_response({ subscribers: subs })
end

get '/api/admin/newsletter/:key_id/export' do
  admin_auth!
  subs = DB.execute(
    'SELECT email, created_at FROM newsletter_subscribers WHERE api_key_id = ? ORDER BY created_at DESC',
    params[:key_id]
  )
  content_type 'text/csv'
  attachment "newsletter_#{params[:key_id]}.csv"
  rows = subs.map { |s| "#{s['email']},#{s['created_at']}" }
  "email,date\n" + rows.join("\n")
end

delete '/api/admin/newsletter/:id' do
  admin_auth!
  DB.execute('DELETE FROM newsletter_subscribers WHERE id = ?', params[:id])
  LOGGER.warn("Abonné newsletter supprimé | ID: #{params[:id]}")
  json_response({ success: true })
end

# ─────────────────────────────────────────
#  Routes Admin — Campagnes newsletter
# ─────────────────────────────────────────
get '/api/admin/newsletter/:key_id/campaigns' do
  admin_auth!
  campaigns = DB.execute(
    'SELECT id, subject, status, sent_count, failed_count, created_at FROM newsletter_campaigns WHERE api_key_id = ? ORDER BY created_at DESC',
    params[:key_id]
  )
  json_response({ campaigns: campaigns })
end

post '/api/admin/newsletter/:key_id/campaigns' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read) rescue {}

  key = DB.get_first_row('SELECT * FROM api_keys WHERE id = ?', params[:key_id])
  halt 404, json_response({ error: 'Projet introuvable' }, 404) unless key

  subject = sanitize_header_value(data['subject'], max_len: 250)
  html    = data['html'].to_s.strip
  text    = data['text'].to_s.strip

  if subject.nil? || subject.empty?
    halt 400, json_response({ error: 'Sujet requis' }, 400)
  end
  if html.empty? && text.empty?
    halt 400, json_response({ error: 'Contenu requis (texte ou HTML)' }, 400)
  end

  subscribers = DB.execute(
    'SELECT * FROM newsletter_subscribers WHERE api_key_id = ?',
    [params[:key_id]]
  )

  campaign_id = SecureRandom.uuid
  sent_count   = 0
  failed_count = 0

  base_url = data['base_url'].to_s.strip
  base_url = request.base_url if base_url.empty?

  subscribers.each do |sub|
    unsubscribe_url = "#{base_url}/api/unsubscribe/#{sub['unsubscribe_token']}"
    footer_html = "<p style=\"font-size:11px;color:#999;margin-top:24px\">" \
      "<a href=\"#{unsubscribe_url}\" style=\"color:#999\">Se désinscrire</a></p>"
    footer_text = "\n\n---\nSe désinscrire : #{unsubscribe_url}"

    begin
      message = Mail.new do
        from    "#{sanitize_header_value(key['smtp_from_name'])} <#{key['smtp_from_email']}>"
        to      sub['email']
        subject subject
        text_part { body(text.empty? ? nil : text + footer_text) } unless text.empty?
        html_part { content_type 'text/html; charset=UTF-8'; body(html.empty? ? nil : html + footer_html) } unless html.empty?
      end

      message.delivery_method :smtp, {
        address:              key['smtp_host'],
        port:                 key['smtp_port'],
        user_name:            key['smtp_user'],
        password:             key['smtp_pass'],
        authentication:       :plain,
        enable_starttls_auto: true,
        open_timeout:         10,
        read_timeout:         20
      }

      message.deliver!
      sent_count += 1
    rescue => e
      LOGGER.error("Campagne: échec envoi à #{sub['email']} | #{e.message}")
      failed_count += 1
    end
  end

  DB.execute(
    'INSERT INTO newsletter_campaigns (id, api_key_id, subject, html, text, status, sent_count, failed_count)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [campaign_id, params[:key_id], subject, html, text, 'sent', sent_count, failed_count]
  )

  LOGGER.info("Campagne envoyée | Projet: #{key['name']} | #{sent_count} envoyés, #{failed_count} échecs")
  json_response({ success: true, sent_count: sent_count, failed_count: failed_count })
end

# ─────────────────────────────────────────
#  Routes Admin — Domaines expéditeur email
# ─────────────────────────────────────────
post '/api/admin/domains' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read)
  id   = SecureRandom.uuid

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

    test_html = <<~HTML
      <div style="font-family:Inter,Arial,sans-serif;background:#080c14;padding:32px 16px">
        <div style="max-width:480px;margin:0 auto;background:#0d1117;border:1px solid #1a2235;border-radius:12px;padding:32px">
          <div style="font-size:18px;font-weight:700;color:#ffffff;margin-bottom:20px">FormTo</div>
          <h2 style="color:#10b981;margin:0 0 12px;font-size:18px">✅ Configuration SMTP valide</h2>
          <p style="color:#8b9cc4;line-height:1.6;font-size:14px;margin:0 0 20px">
            Si vous recevez ce message, votre configuration SMTP fonctionne correctement
            et FormTo pourra envoyer vos emails sans problème.
          </p>
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <tr><td style="color:#4a5a7a;padding:6px 0">Hôte</td><td style="color:#c9d1e0;text-align:right">#{Rack::Utils.escape_html(smtp_host.to_s)}</td></tr>
            <tr><td style="color:#4a5a7a;padding:6px 0">Port</td><td style="color:#c9d1e0;text-align:right">#{smtp_port}</td></tr>
            <tr><td style="color:#4a5a7a;padding:6px 0">Utilisateur</td><td style="color:#c9d1e0;text-align:right">#{Rack::Utils.escape_html(smtp_user.to_s)}</td></tr>
          </table>
        </div>
      </div>
    HTML

    message = Mail.new do
      from    "#{from_name} <#{from_email}>"
      to      from_email
      subject 'FormTo — Test SMTP ✅'
      text_part do
        body "Si vous recevez ce message, votre configuration SMTP est correcte.\n\nHôte: #{smtp_host}\nPort: #{smtp_port}\nUtilisateur: #{smtp_user}"
      end
      html_part do
        content_type 'text/html; charset=UTF-8'
        body test_html
      end
    end

    message.delivery_method :smtp, {
      address:              smtp_host,
      port:                 smtp_port,
      user_name:            smtp_user,
      password:             smtp_pass,
      authentication:       :plain,
      enable_starttls_auto: true,
      open_timeout:         10,
      read_timeout:         10
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
# La version courante est injectée au build de l'image Docker via
# --build-arg APP_VERSION=v1.4 (voir Dockerfile), plutôt que codée en
# dur ici — ça évite d'oublier de mettre à jour cette constante à
# chaque release. En dev sans build-arg, retombe sur 'dev'.
CURRENT_VERSION = ENV.fetch('APP_VERSION', 'dev').freeze
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
    latest_version:   latest,
    docker_image:     DOCKER_IMAGE
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