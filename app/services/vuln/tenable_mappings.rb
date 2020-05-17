# frozen_string_literal: true

# Vuln module
module Vuln
  # TenableMappings concern
  module TenableMappings
    extend ActiveSupport::Concern

    # Class methods in concern
    module ClassMethods
      def map_asset_vuln(vuln)
        { external: vuln['id'], hostname: vuln['hostname'], ipv4: vuln['ipv4'], netbios_name: vuln['netbios_name'],
          fqdn: vuln['fqdn'], first_seen: vuln['first_seen'], last_seen: vuln['last_seen'] }
      end

      def map_vuln(vuln)
        { external: vuln['plugin_id'], name: vuln['plugin_name'], state: vuln['vulnerability_state'],
          severity: map_severity(vuln['severity']) }
      end

      def map_severity(sev)
        case sev
        when 4 then 'Critical'
        when 3 then 'High'
        when 2 then 'Medium'
        when 1 then 'Low'
        when 0 then 'Information'
        else "Unknown: #{sev}"
        end
      end

      def map_asset(asset)
        { external: asset['id'], last_ipv4: asset['ipv4'].first, fqdn: asset['fqdn'].first,
          netbios_name: asset['netbios_name'].first, operating_system: asset['operating_system'].first }
      end

      def map_asset_chunk(asset)
        { external: asset['id'], last_ipv4: asset['ipv4s'].first, fqdn: asset['fqdns'].first,
          netbios_name: asset['netbios_names'].first, operating_system: asset['operating_systems'].first }
      end
    end
  end
end
