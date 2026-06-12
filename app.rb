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

DB.execute_batch <<-SQL
  CREATE TABLE IF NOT EXISTS api_keys (
    id             TEXT PRIMARY KEY,
    name           TEXT,
    api_key        TEXT UNIQUE,
    smtp_host      TEXT,
    smtp_port      INTEGER,
    smtp_user      TEXT,
    smtp_pass      TEXT,
    smtp_from_email TEXT,
    smtp_from_name  TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
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
SQL

LOGGER.info("DB initialisée → #{DB_PATH}")
LOGGER.info("Clés chargées  → #{DB.execute('SELECT count(*) FROM api_keys').first[0]}")

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

  from_email   = from || @key_config['smtp_from_email']
  from_domain  = from_email.split('@').last
  is_own_email = (from_email == @key_config['smtp_from_email'])
  allowed      = DB.get_first_row(
    'SELECT * FROM allowed_domains WHERE api_key_id = ? AND domain = ?',
    @key_config['id'], from_domain
  )

  unless is_own_email || allowed
    msg = "Domaine non autorisé: #{from_domain}"
    LOGGER.warn("#{msg} | Tenant: #{@key_config['name']}")
    log_request(status: 'error', error_msg: msg, recipient: to, subject: subject)
    halt 403, json_response({ error: "Le domaine '#{from_domain}' n'est pas autorisé." }, 403)
  end

  LOGGER.info("Envoi | #{from_email} → #{to} | \"#{subject}\" | Tenant: #{@key_config['name']}")

  begin
    smtp_from_name  = @key_config['smtp_from_name']
    smtp_from_email_config = @key_config['smtp_from_email']
    smtp_host       = @key_config['smtp_host']
    smtp_port       = @key_config['smtp_port']
    smtp_user       = @key_config['smtp_user']
    smtp_pass       = @key_config['smtp_pass']

    message = Mail.new do
      from    "#{smtp_from_name} <#{from_email}>"
      to      to
      subject subject
      text_part { body text } if text
      html_part { body html } if html
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
  keys    = DB.execute('SELECT id, name, api_key, smtp_from_email, smtp_from_name, created_at FROM api_keys')
  domains = DB.execute('SELECT id, api_key_id, domain FROM allowed_domains')
  LOGGER.info("Config admin lue | #{keys.length} clé(s) | #{domains.length} domaine(s)")
  json_response({ keys: keys, domains: domains })
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

  begin
    DB.execute(
      'INSERT INTO api_keys (id, name, api_key, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from_email, smtp_from_name)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, data['name'], api_key, data['smtp_host'], data['smtp_port'],
       data['smtp_user'], data['smtp_pass'], data['smtp_from_email'], data['smtp_from_name']]
    )
    LOGGER.info("Clé créée | #{data['name']} | ID: #{id}")
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

  begin
    DB.execute(
      'UPDATE api_keys SET name=?, smtp_host=?, smtp_port=?, smtp_user=?, smtp_pass=?, smtp_from_email=?, smtp_from_name=? WHERE id=?',
      [data['name'], data['smtp_host'], data['smtp_port'], data['smtp_user'],
       data['smtp_pass'], data['smtp_from_email'], data['smtp_from_name'], params[:id]]
    )
    LOGGER.info("Clé mise à jour | ID: #{params[:id]}")
    json_response({ success: true })
  rescue SQLite3::Exception => e
    LOGGER.error("Erreur MAJ clé | #{e.message}")
    halt 500, json_response({ error: "DB: #{e.message}" }, 500)
  end
end

delete '/api/admin/keys/:id' do
  admin_auth!
  DB.execute('DELETE FROM api_keys WHERE id = ?', params[:id])
  LOGGER.warn("Clé supprimée | ID: #{params[:id]}")
  json_response({ success: true })
end

# ─────────────────────────────────────────
#  Routes Admin — Domaines
# ─────────────────────────────────────────
post '/api/admin/domains' do
  admin_auth!
  request.body.rewind
  data = JSON.parse(request.body.read)
  id   = SecureRandom.uuid

  begin
    DB.execute('INSERT INTO allowed_domains (id, api_key_id, domain) VALUES (?, ?, ?)',
               [id, data['api_key_id'], data['domain']])
    LOGGER.info("Domaine ajouté | #{data['domain']}")
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
    smtp_host = data['smtp_host']
    smtp_port = data['smtp_port'].to_i
    smtp_user = data['smtp_user']
    smtp_pass = data['smtp_pass']
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
#  Check Update
# ────
get '/api/admin/check-update' do
  admin_auth!
  begin
    require 'net/http'
    require 'uri'

    uri = URI('https://hub.docker.com/v2/repositories/yidirk/formto/tags/latest')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 5
    http.open_timeout = 5

    req = Net::HTTP::Get.new(uri)
    req['Accept'] = 'application/json'

    response = http.request(req)
    data = JSON.parse(response.body)

    remote_digest = data.dig('images', 0, 'digest')
    last_pushed   = data['tag_last_pushed']


    local_digest_path = '/etc/formto-digest'
    local_digest = File.exist?(local_digest_path) ? File.read(local_digest_path).strip : nil

    update_available = local_digest && remote_digest && local_digest != remote_digest

    LOGGER.info("Check update | remote=#{remote_digest&.slice(0,20)} local=#{local_digest&.slice(0,20)}")
    json_response({
                    update_available: update_available,
                    last_pushed: last_pushed,
                    remote_digest: remote_digest&.slice(0, 20)
                  })
  rescue => e
    LOGGER.warn("Check update échoué | #{e.message}")
    json_response({ update_available: false, error: e.message })
  end
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

  query  = status ? "WHERE status = '#{DB.quote(status)}'" : ''
  logs   = DB.execute(
    "SELECT * FROM request_logs #{query} ORDER BY created_at DESC LIMIT ? OFFSET ?",
    [limit, offset]
  )
  total  = DB.execute("SELECT count(*) FROM request_logs #{query}").first[0]

  json_response({ logs: logs, total: total, limit: limit, offset: offset })
end

# ─────────────────────────────────────────
#  UI
# ─────────────────────────────────────────
get '/' do
  send_file File.join(settings.public_folder, 'index.html')
end