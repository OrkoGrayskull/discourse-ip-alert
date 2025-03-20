# frozen_string_literal: true

# name: discourse-ip-alert
# about: Sends an internal notification when a user logs in from a suspicious IP address.
# version: 1.0
# authors: OrkoGrayskull
# url: https://github.com/OrkoGrayskull/discourse-ip-alert
# required_version: 2.7.0

enabled_site_setting :ip_alert_enabled
enabled_site_setting :ip_alert_suspicious_ips

module ::DiscourseIpAlert
  PLUGIN_NAME = "discourse-ip-alert"

  require 'ipaddr'

  def self.extract_ip(user)
    ip = user.ip_address.to_s
    Rails.logger.info("[DiscourseIpAlert] Extracted IP: #{ip.inspect}")
    ip
  rescue => e
    Rails.logger.error("[DiscourseIpAlert] extract_ip Error: #{e.message}")
    nil
  end

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

  def self.send_warning_notification(user, ip_address)
    admin_users = User.where(admin: true)
    return if admin_users.empty?

    message_title = "⚠️ Verdächtige Anmeldung erkannt!"

    admin_users.each do |admin|
      begin
        Notification.create!(
          notification_type: Notification.types[:custom],
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
end

after_initialize do
  reloadable_patch do |plugin|
    on(:user_logged_in) do |user|
      ::DiscourseIpAlert.process_user_login(user)
    end
  end
end
