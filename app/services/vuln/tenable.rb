# frozen_string_literal: true

require 'amazing_print'

# Vuln::Tenable::retrieve_assets; nil
# Vuln::Tenable::retrieve_vulnerabilities; nil
# Vuln::Tenable::retrieve_asset_vulns; nil

module Vuln
  # Tenable importer service
  class Tenable
    class << self
      ACCESS_KEY = ''
      SECRET_KEY = ''

      def retrieve_assets
        url = URI('https://cloud.tenable.com/assets')
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        assets = retrieve_assets_internal(http, url)
        ingest_assets(assets)
      end

      def retrieve_vulnerabilities
        url = URI('https://cloud.tenable.com/workbenches/vulnerabilities')
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        vulns = retrieve_vulnerabilities_internal(http, url)
        ingest_vulnerabilities(vulns)
      end

      def retrieve_asset_vulns(plugin_id = 51_192)
        # url = URI('https://cloud.tenable.com/workbenches/assets/f678a680-aced-4412-8dec-164e639ccbc5/vulnerabilities')
        url = URI("https://cloud.tenable.com/workbenches/vulnerabilities/#{plugin_id}/outputs")
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        vulnerability = Vulnerability.find_by!(external: plugin_id)
        vulns = retrieve_asset_vulns_internal(http, url, vulnerability)
        ingest_asset_vulns(vulns)
      end

      def retrieve_assets_internal(http, url)
        request = Net::HTTP::Get.new(url, 'x-apikeys' => "accessKey=#{ACCESS_KEY};secretKey=#{SECRET_KEY}",
                                          'accept' => 'application/json')
        response = http.request(request)
        body = JSON.parse(response.body)
        assets = body['assets'].collect { |asset| map_asset(asset) }
        assets.collect { |asset| Asset.new(asset) }
      end

      def map_asset(asset)
        { external: asset['id'], last_ipv4: asset['ipv4'].first, fqdn: asset['fqdn'].first,
          netbios_name: asset['netbios_name'].first, operating_system: asset['operating_system'].first }
      end

      def ingest_assets(assets)
        Asset.import assets, validate: true
      end

      def retrieve_vulnerabilities_internal(http, url)
        request = Net::HTTP::Get.new(url, 'x-apikeys' => "accessKey=#{ACCESS_KEY};secretKey=#{SECRET_KEY}",
                                          'accept' => 'application/json')
        response = http.request(request)
        body = JSON.parse(response.body)
        vulns = body['vulnerabilities'].collect { |vuln| map_vuln(vuln) }
        vulns.collect { |asset| Vulnerability.new(asset) }

        # [0] "count",
        #     [1] "plugin_family",
        #     [2] "plugin_id",
        #     [3] "plugin_name",
        #     [4] "vulnerability_state",
        #     [5] "accepted_count",
        #     [6] "recasted_count",
        #     [7] "counts_by_severity",
        #     [8] "severity"
      end

      def retrieve_asset_vulns_internal(http, url, vulnerability)
        request = Net::HTTP::Get.new(url, 'x-apikeys' => "accessKey=#{ACCESS_KEY};secretKey=#{SECRET_KEY}",
                                          'accept' => 'application/json')
        response = http.request(request)
        body = JSON.parse(response.body)
        vulns, asset_ids = locate_assets_for_vulns(body)
        map_asset_vulns_to_records(vulns, asset_ids, vulnerability)
        # {
        #     "hostname" => "10.87.x.x",
        #     "id" => "1acf743d-47c6-458d-8030-dc026d926427",
        #     "uuid" => "1acf743d-47c6-458d-8030-dc026d926427",
        #     "netbios_name" => "HOSTNAME",
        #     "fqdn" => nil,
        #     "ipv4" => "10.87.x.x",
        #     "first_seen" => "2020-05-14T19:59:06.350Z",
        #     "last_seen" => "2020-05-14T19:59:06.350Z"
        # }
      end

      def locate_assets_for_vulns(body)
        asset_vulns = body['outputs'][0]['states'][0]['results'][0]['assets']
        vulns = asset_vulns.collect { |vuln| map_asset_vuln(vuln) }
        asset_ids = vulns.collect { |x| x[:external] }
        [vulns, asset_ids]
      end

      def map_asset_vulns_to_records(vulns, asset_ids, vulnerability)
        assets = Asset.where(external: asset_ids)
        vulns.collect do |asset_vuln|
          found_asset = assets.detect { |a2| a2.external == asset_vuln[:external] }
          puts "Asset not found: #{asset_vuln[:external]}" unless found_asset
          attrs = asset_vuln.merge(asset_id: found_asset.try(:id), vulnerability_id: vulnerability.try(:id))
          AssetVulnerability.new(attrs)
        end
      end

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

      def ingest_vulnerabilities(vulns)
        Vulnerability.import vulns, validate: true
      end

      def ingest_asset_vulns(vulns)
        AssetVulnerability.import vulns, validate: true
      end
    end
  end
end
