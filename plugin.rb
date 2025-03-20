# frozen_string_literal: true

# name: discourse-ip-alert
# about: Sends an internal notification when a user logs in from a suspicious IP address.
# version: 1.2
# authors: OrkoGrayskull
# url: https://github.com/OrkoGrayskull/discourse-ip-alert
# required_version: 2.7.0

enabled_site_setting :ip_alert_enabled
enabled_site_setting :ip_alert_suspicious_ips
enabled_site_setting :ip_alert_interval_minutes

module ::DiscourseIpAlert
  PLUGIN_NAME = "discourse-ip-alert"

  require 'ipaddr'

  # Extrahiert die IP-Adresse des Nutzers
  def self.extract_ip(user)
    ip = user.ip_address.to_s
    Rails.logger.info("[DiscourseIpAlert] Extracted IP: #{ip.inspect}")
    ip
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] extract_ip Error: #{e.message}")
    nil
  end

  # Prüft, ob die übergebene IP in der Blockliste enthalten ist
  def self.ip_blocked?(ip_address)
    return false if ip_address.blank?

    blocked_ips = SiteSetting.ip_alert_suspicious_ips.to_s.split(",").map(&:strip)
    Rails.logger.info("[DiscourseIpAlert] Blocked IPs: #{blocked_ips.inspect}")

    blocked_ips.any? do |blocked|
      if blocked.include?('*')
        pattern = blocked.gsub("*", "\\d{1,3}")
        regex = /^#{pattern}$/
        ip_address.match?(regex)
      else
        begin
          IPAddr.new(blocked).include?(ip_address)
        rescue IPAddr::InvalidAddressError
          false
        end
      end
    end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] ip_blocked? Error: #{e.message}")
    false
  end

  # Sendet eine interne Notification an alle Admins, wenn eine verdächtige IP erkannt wird
  def self.send_warning_notification(user, ip_address)
    admin_users = User.where(admin: true)
    return if admin_users.empty?

    message_title = "⚠️ Verdächtige Anmeldung erkannt!"

    admin_users.each do |admin|
      begin
        Notification.create!(
          notification_type: Notification.types[:flagged_post],
          user_id: admin.id,
          data: {
            display_username: user.username,
            topic_title: message_title
          }.to_json
        )
        Rails.logger.info("[DiscourseIpAlert] Notification sent to #{admin.username}")
      rescue => e
        Rails.logger.error("[DiscourseIpAlert] Error sending notification to #{admin.username}: #{e.message}")
      end
    end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] send_warning_notification Error: #{e.message}")
  end

  # Verarbeitet den Login eines Nutzers: Extrahiert die IP, prüft sie und sendet ggf. eine Notification
  def self.process_user_login(user)
    Rails.logger.info("[DiscourseIpAlert] Processing login for user: #{user.username}")

    ip_address = extract_ip(user)
    return unless ip_address.present?

    if ip_blocked?(ip_address)
      Rails.logger.warn("[DiscourseIpAlert] Suspicious IP detected: #{ip_address}")
      send_warning_notification(user, ip_address)
    else
      Rails.logger.info("[DiscourseIpAlert] IP #{ip_address} is safe.")
    end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] process_user_login Error: #{e.message}")
  end

  # Periodischer Check: Überprüft alle Nutzer, die in den letzten 6 Stunden (oder entsprechend des Intervalls) aktiv waren.
  def self.process_recent_user_ips
    Rails.logger.info("[DiscourseIpAlert] Running periodic IP check for users active in the last #{SiteSetting.ip_alert_interval_minutes} minutes")
    User.real.where("last_seen_at > ?", SiteSetting.ip_alert_interval_minutes.to_i.minutes.ago).find_each do |user|
      ip_address = extract_ip(user)
      next unless ip_address.present?

      if ip_blocked?(ip_address)
        Rails.logger.warn("[DiscourseIpAlert] Suspicious IP detected for #{user.username}: #{ip_address}")
        send_warning_notification(user, ip_address)
      else
        Rails.logger.info("[DiscourseIpAlert] IP #{ip_address} for #{user.username} is safe")
      end
    end
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] process_recent_user_ips Error: #{e.message}")
  end
end

after_initialize do
  reloadable_patch do |plugin|
    on(:user_logged_in) do |user|
      ::DiscourseIpAlert.process_user_login(user)
    end
  end

  module ::Jobs
    class CheckUserIPs < ::Jobs::Scheduled
      every { SiteSetting.ip_alert_interval_minutes.to_i.minutes }  # Dynamischer Intervall, z. B. 360 Minuten (6 Stunden) per Standard

      def execute(args)
        ::DiscourseIpAlert.process_recent_user_ips
      end
    end
  end
end
