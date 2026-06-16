# frozen_string_literal: true

# name: discourse-ip-alert
# about: Sends an internal admin PM and optional email when a user logs in from a suspicious IP address.
# version: 2.1.4
# authors: OrkoGrayskull
# url: https://github.com/OrkoGrayskull/discourse-ip-alert
# required_version: 3.3.0

enabled_site_setting :ip_alert_enabled

module ::DiscourseIpAlert
  PLUGIN_NAME = "discourse-ip-alert"
  REDIS_PREFIX = "discourse-ip-alert"

  require "ipaddr"

  def self.enabled?
    SiteSetting.ip_alert_enabled
  end

  def self.rules
    SiteSetting.ip_alert_suspicious_ips
      .to_s
      .split(/[,\|]/)
      .map(&:strip)
      .reject(&:blank?)
      .uniq
  end

  def self.valid_ip?(value)
    IPAddr.new(value.to_s)
    true
  rescue IPAddr::InvalidAddressError
    false
  end

  def self.ip_to_addr(value)
    IPAddr.new(value.to_s)
  rescue IPAddr::InvalidAddressError
    nil
  end

  def self.ipv4_wildcard_match?(ip_address, rule)
    ip_parts = ip_address.to_s.split(".")
    rule_parts = rule.to_s.split(".")

    return false unless ip_parts.length == 4
    return false unless rule_parts.length == 4

    return false unless ip_parts.all? do |part|
      part.match?(/\A\d{1,3}\z/) && part.to_i.between?(0, 255)
    end

    rule_parts.zip(ip_parts).all? do |rule_part, ip_part|
      next true if rule_part == "*"

      rule_part.match?(/\A\d{1,3}\z/) &&
        rule_part.to_i.between?(0, 255) &&
        rule_part.to_i == ip_part.to_i
    end
  end

  def self.matching_rule(ip_address)
    return nil if ip_address.blank?

    ip = ip_to_addr(ip_address)
    return nil if ip.blank?

    rules.find do |rule|
      if rule.include?("*")
        ipv4_wildcard_match?(ip_address, rule)
      else
        begin
          IPAddr.new(rule).include?(ip)
        rescue IPAddr::Error
          Rails.logger.warn("[DiscourseIpAlert] Ungültige IP-Regel ignoriert: #{rule.inspect}")
          false
        end
      end
    end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] Fehler beim IP-Abgleich: #{e.class}: #{e.message}")
    nil
  end

  def self.recent_login_log_for(user)
    return nil if !defined?(UserAuthTokenLog)

    UserAuthTokenLog
      .where(user_id: user.id, action: "generate")
      .order(created_at: :desc)
      .first
  rescue => e
    Rails.logger.warn("[DiscourseIpAlert] Konnte UserAuthTokenLog nicht lesen: #{e.class}: #{e.message}")
    nil
  end

  def self.latest_auth_token_for(user)
    return nil if !defined?(UserAuthToken)

    UserAuthToken
      .where(user_id: user.id)
      .order(created_at: :desc)
      .first
  rescue => e
    Rails.logger.warn("[DiscourseIpAlert] Konnte UserAuthToken nicht lesen: #{e.class}: #{e.message}")
    nil
  end

  def self.login_context_for(user)
    log = recent_login_log_for(user)

    if log&.client_ip.present? && log.created_at > 5.minutes.ago
      return {
        ip_address: log.client_ip.to_s,
        user_agent: log.user_agent.to_s,
        path: log.path.to_s,
        created_at: log.created_at,
        source: "UserAuthTokenLog"
      }
    end

    token = latest_auth_token_for(user)

    {
      ip_address: token&.client_ip.to_s.presence || user.ip_address.to_s,
      user_agent: token&.user_agent.to_s,
      path: nil,
      created_at: token&.created_at,
      source: token.present? ? "UserAuthToken" : "User"
    }
  end

  def self.cooldown_key(user_id, ip_address)
    "#{REDIS_PREFIX}:alerted:#{user_id}:#{ip_address}"
  end

  def self.cooldown_active?(user_id, ip_address)
    Discourse.redis.get(cooldown_key(user_id, ip_address)).present?
  end

  def self.mark_cooldown(user_id, ip_address)
    ttl = SiteSetting.ip_alert_notification_cooldown_minutes.to_i.minutes.to_i
    ttl = 720.minutes.to_i if ttl <= 0

    Discourse.redis.setex(cooldown_key(user_id, ip_address), ttl, "1")
  end

  def self.escape_backticks(value)
    value.to_s.gsub("`", "\\`")
  end

  def self.message_title(user, ip_address)
    title = "IP-Alert: #{user.username} von #{ip_address}"
    title.truncate(SiteSetting.max_topic_title_length, separator: " ")
  end

  def self.message_body(user, ip_address, matched_rule, context, markdown: true)
    if markdown
      <<~MD
        Verdächtige Anmeldung erkannt.

        Nutzer: @#{user.username}
        Nutzerprofil: #{Discourse.base_url}/u/#{user.username}
        Admin-Profil: #{Discourse.base_url}/admin/users/#{user.id}/#{user.username}
        IP-Adresse: `#{escape_backticks(ip_address)}`
        Trefferregel: `#{escape_backticks(matched_rule)}`
        Quelle: `#{escape_backticks(context[:source])}`
        Zeitpunkt: `#{escape_backticks(context[:created_at] || Time.zone.now)}`
        Pfad: `#{escape_backticks(context[:path].presence || "-")}`
        User-Agent: `#{escape_backticks(context[:user_agent].presence || "-")}`

        Diese Meldung wurde automatisch durch das Plugin `#{PLUGIN_NAME}` erzeugt.
      MD
    else
      <<~TEXT
        Verdächtige Anmeldung erkannt.

        Nutzer: @#{user.username}
        Nutzerprofil: #{Discourse.base_url}/u/#{user.username}
        Admin-Profil: #{Discourse.base_url}/admin/users/#{user.id}/#{user.username}
        IP-Adresse: #{ip_address}
        Trefferregel: #{matched_rule}
        Quelle: #{context[:source]}
        Zeitpunkt: #{context[:created_at] || Time.zone.now}
        Pfad: #{context[:path].presence || "-"}
        User-Agent: #{context[:user_agent].presence || "-"}

        Diese Meldung wurde automatisch durch das Plugin #{PLUGIN_NAME} erzeugt.
      TEXT
    end
  end

  def self.admin_usernames
    User.real
      .where(admin: true, active: true)
      .where(staged: false)
      .where.not(id: Discourse.system_user.id)
      .pluck(:username)
      .join(",")
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] Konnte Admin-Nutzernamen nicht lesen: #{e.class}: #{e.message}")
    ""
  end

  def self.send_admin_pm(user, ip_address, matched_rule, context)
    usernames = admin_usernames

    if usernames.blank?
      Rails.logger.error("[DiscourseIpAlert] Keine Admin-Empfänger für PM gefunden")
      return
    end

    PostCreator.create!(
      Discourse.system_user,
      title: message_title(user, ip_address),
      raw: message_body(user, ip_address, matched_rule, context, markdown: true),
      archetype: Archetype.private_message,
      target_usernames: usernames,
      skip_validations: true
    )

    Rails.logger.info("[DiscourseIpAlert] Admin-PM erstellt: user=#{user.username}, ip=#{ip_address}")
  end

  def self.admin_email_recipients
    User.real
      .where(admin: true, active: true)
      .where(staged: false)
      .where.not(id: Discourse.system_user.id)
  end

  def self.email_for(user)
    user.primary_email&.email.presence || user.email.to_s.presence
  rescue => e
    Rails.logger.warn("[DiscourseIpAlert] Konnte Mailadresse für user_id=#{user&.id} nicht lesen: #{e.class}: #{e.message}")
    nil
  end

  def self.send_admin_emails(user, ip_address, matched_rule, context)
    return unless SiteSetting.ip_alert_email_admins

    subject = message_title(user, ip_address)
    body = message_body(user, ip_address, matched_rule, context, markdown: false)

    Rails.logger.warn("[DiscourseIpAlert] Admin-Mail-Benachrichtigung aktiv, enqueue Admin-Mails")

    admin_email_recipients.find_each do |admin|
      Jobs.enqueue(
        :send_ip_alert_email,
        admin_id: admin.id,
        subject: subject,
        body: body
      )
    end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] Admin-Mail-Benachrichtigung fehlgeschlagen: #{e.class}: #{e.message}")
  end

  def self.process_login(user, context = nil)
    return unless enabled?
    return if user.blank?
    return if user.id.to_i <= 0
    return if user.respond_to?(:bot?) && user.bot?

    context ||= login_context_for(user)
    ip_address = context[:ip_address].to_s

    return if ip_address.blank?
    return unless valid_ip?(ip_address)

    matched_rule = matching_rule(ip_address)
    return if matched_rule.blank?

    if cooldown_active?(user.id, ip_address)
      Rails.logger.info("[DiscourseIpAlert] Alert übersprungen, Cooldown aktiv: user_id=#{user.id}, ip=#{ip_address}")
      return
    end

    send_admin_pm(user, ip_address, matched_rule, context)
    send_admin_emails(user, ip_address, matched_rule, context)
    mark_cooldown(user.id, ip_address)

    Rails.logger.warn("[DiscourseIpAlert] Verdächtige Anmeldung: user=#{user.username}, ip=#{ip_address}, rule=#{matched_rule}")
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] process_login Fehler: #{e.class}: #{e.message}")
  end

  def self.process_recent_logins
    return unless enabled?
    return unless defined?(UserAuthTokenLog)

    since = SiteSetting.ip_alert_recent_login_window_minutes.to_i.minutes.ago

    UserAuthTokenLog
      .where(action: "generate")
      .where("created_at > ?", since)
      .where.not(client_ip: nil)
      .find_each do |log|
        user = User.real.find_by(id: log.user_id)
        next if user.blank?

        process_login(
          user,
          {
            ip_address: log.client_ip.to_s,
            user_agent: log.user_agent.to_s,
            path: log.path.to_s,
            created_at: log.created_at,
            source: "UserAuthTokenLog"
          }
        )
      end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] process_recent_logins Fehler: #{e.class}: #{e.message}")
  end
end

after_initialize do
  on(:user_logged_in) do |user|
    ::DiscourseIpAlert.process_login(user)
  end

  module ::Jobs
    class SendIpAlertEmail < ::Jobs::Base
      sidekiq_options queue: "low", retry: false

      def execute(args)
        admin = User.real.find_by(id: args[:admin_id])
        return if admin.blank?
        return if !admin.admin?
        return if !admin.active?
        return if admin.staged?

        to_address = ::DiscourseIpAlert.email_for(admin)
        return if to_address.blank?

        message = ActionMailer::Base.mail(
          to: to_address,
          from: SiteSetting.notification_email,
          subject: args[:subject].to_s,
          body: args[:body].to_s,
          content_type: "text/plain; charset=UTF-8"
        )

        message["X-Auto-Response-Suppress"] = "All"
        message["X-Discourse-Sender"] = "discourse-ip-alert"

        Email::Sender.new(message, :admin_login, admin).send

        Rails.logger.warn("[DiscourseIpAlert] Admin-Mail versendet: admin=#{admin.username}, to=#{to_address}")
      rescue => e
        Rails.logger.error("[DiscourseIpAlert] Versand der Admin-Mail fehlgeschlagen: #{e.class}: #{e.message}")
      end
    end

    class CheckSuspiciousLoginIPs < ::Jobs::Scheduled
      every 6.hours
      sidekiq_options retry: false

      def execute(_args)
        ::DiscourseIpAlert.process_recent_logins
      end
    end
  end
end
