# frozen_string_literal: true

# Vuln modules
module Vuln
  # TenableAssets concern
  module TenableVulns
    extend ActiveSupport::Concern

    # Class methods in concern
    module ClassMethods
      def retrieve_vulns_chunk_status(uuid)
        url = URI("https://cloud.tenable.com/vulns/export/#{uuid}/status")
        body = get_request(url)
        puts "Status: #{body['status']}"
        puts "Chunks: #{body['chunks_available']}"
      end

      def retrieve_vulns_chunk(uuid, chunks = [1])
        chunks.each do |chunk|
          puts "Retrieving chunk #{chunk} of vulnerability export #{uuid}..."
          url = URI("https://cloud.tenable.com/vulns/export/#{uuid}/chunks/#{chunk}")
          body = get_request(url)

          vulns = map_bulk_vulns(body)
          asset_ids = vulns.collect { |x| x[:external] }.uniq
          plugins = obtain_related_plugins(body)
          converted = asset_vulns_plugins_to_records(vulns, asset_ids, plugins)
          ingest_asset_vulns(converted)

          #     "output" => "\nA CIFS server is running on this port.\n",
          # "severity" => "info",
          #     "severity_id" => 0,
          #     "severity_default_id" => 0,
          #     "severity_modification_type" => "NONE",
          #     "first_found" => "2020-04-20T08:40:40.060Z",
          #     "last_found" => "2020-04-20T08:40:40.060Z",
          #     "state" => "OPEN"
          # }
        end

        # attributes:
        # asset
        #   device_type fqdn hostname uuid ipv4 last_unauthenticated_results mac_address netbios_name
        #   netbios_workgroup operating_system network_id tracked
        # output
        # plugin
        # port
        # scan
        # severity
        # severity_id
        # severity_default_id
        # severity_modification_type
        # first_found
        # last_found
        # state
      end

      def map_bulk_vulns(body)
        body.collect do |vuln|
          asset = vuln['asset']
          { external: asset['uuid'], fqdn: asset['fqdn'], netbios_name: asset['netbios_name'],
            ipv4: asset['ipv4'], operating_system: asset['operating_system']&.first,
            plugin_id: vuln['plugin']['id'], severity: vuln['severity'], state: vuln['state'],
            first_seen: vuln['first_found'], last_seen: vuln['last_found'] }
        end
      end

      def obtain_related_plugins(body)
        plugin_ids = body.collect { |x| x['plugin']['id'] }.uniq
        Vulnerability.where(external: plugin_ids)
      end

      def asset_vulns_plugins_to_records(vulns, asset_ids, plugins)
        assets = Asset.where(external: asset_ids)
        vulns.collect do |asset_vuln|
          found_asset, found_plugin = locate_assets_and_plugins(assets, asset_vuln, plugins)
          attrs = asset_vuln.merge(asset_id: found_asset&.id, vulnerability_id: found_plugin&.id).except(:plugin_id)
          AssetVulnerability.new(attrs)
        end
      end

      def locate_assets_and_plugins(assets, asset_vuln, plugins)
        found_asset = assets.detect { |a2| a2.external == asset_vuln[:external] }
        puts "Asset not found: #{asset_vuln[:external]}" unless found_asset
        found_plugin = plugins.detect { |plugin| plugin.external == asset_vuln[:plugin_id] }
        puts "Plugin not found: #{asset_vuln[:plugin_id]}" unless found_plugin
        [found_asset, found_plugin]
      end

      def retrieve_vulnerabilities
        url = URI('https://cloud.tenable.com/workbenches/vulnerabilities')
        vulns = retrieve_vulnerabilities_internal(url)
        ingest_vulnerabilities(vulns)
      end

      def retrieve_all_asset_vulns
        vulns = Vulnerability.all
        vulns.each do |plugin|
          puts "Retrieving plugin #{plugin.external}..."
          retrieve_asset_vulns(plugin.external, plugin)
        end
      end

      def retrieve_asset_vulns(plugin_id, plugin = nil)
        # url = URI('https://cloud.tenable.com/workbenches/assets/f678a680-aced-4412-8dec-164e639ccbc5/vulnerabilities')
        url = URI("https://cloud.tenable.com/workbenches/vulnerabilities/#{plugin_id}/outputs")
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        vulnerability = plugin || Vulnerability.find_by!(external: plugin_id)
        vulns = retrieve_asset_vulns_internal(http, url, vulnerability)
        ingest_asset_vulns(vulns)
      end

      def retrieve_vulnerabilities_internal(url)
        body = get_request(url)
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

      def ingest_vulnerabilities(vulns)
        Vulnerability.import vulns, validate: true
      end

      def ingest_asset_vulns(vulns)
        AssetVulnerability.import vulns, validate: true
      end
    end
  end
end
