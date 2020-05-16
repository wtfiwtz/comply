# frozen_string_literal: true

require 'amazing_print'

# asset_status = Vuln::Tenable::request_asset_chunks
# vulns_status = Vuln::Tenable::request_vulns_chunks
# Vuln::Tenable::retrieve_asset_chunk_status(asset_status)
# Vuln::Tenable::retrieve_vulns_chunk_status(vulns_status)
# Vuln::Tenable::retrieve_asset_chunk(asset_status, (1..7).to_a)
# Vuln::Tenable::retrieve_vulns_chunk(vulns_status, (1..101).to_a)
# Vuln::Tenable::retrieve_vulnerabilities; nil
# Vuln::Tenable::retrieve_all_asset_vulns; nil

# Vuln::Tenable::retrieve_assets; nil
# Vuln::Tenable::retrieve_all_asset_vulns; nil
#
# AssetVulnerability.group(:vulnerability_id).count

module Vuln
  # Tenable importer service
  class Tenable
    class << self
      ACCESS_KEY = ''
      SECRET_KEY = ''

      def request_asset_chunks
        url = URI('https://cloud.tenable.com/assets/export')
        body = post_request(url, { chunk_size: 1000 })
        body['export_uuid']
      end

      def request_vulns_chunks
        url = URI('https://cloud.tenable.com/vulns/export')
        body = post_request(url, { chunk_size: 1000 })
        body['export_uuid']
      end

      def retrieve_asset_chunk_status(uuid)
        url = URI("https://cloud.tenable.com/assets/export/#{uuid}/status")
        body = get_request(url)
        puts "Status: #{body['status']}"
        puts "Chunks: #{body['chunks_available']}"
      end

      def retrieve_vulns_chunk_status(uuid)
        url = URI("https://cloud.tenable.com/vulns/export/#{uuid}/status")
        body = get_request(url)
        puts "Status: #{body['status']}"
        puts "Chunks: #{body['chunks_available']}"
      end

      def retrieve_asset_chunk(uuid, chunks = [1])
        chunks.each do |chunk|
          puts "Retrieving chunk #{chunk} of asset export #{uuid}..."
          url = URI("https://cloud.tenable.com/assets/export/#{uuid}/chunks/#{chunk}")
          body = get_request(url)
          assets = body.collect { |asset| map_asset_chunk(asset) }
          converted = assets.collect { |asset| Asset.new(asset) }
          ingest_assets(converted)
        end
      end

      # attributes
      # %w[id has_agent has_plugin_results created_at terminated_at terminated_by updated_at deleted_at deleted_by
      #    first_seen last_seen first_scan_time last_scan_time last_authenticated_scan_date last_licensed_scan_date
      #    last_scan_id last_schedule_id azure_vm_id azure_resource_id gcp_project_id gcp_zone gcp_instance_id
      #    aws_ec2_instance_ami_id aws_ec2_instance_id agent_uuid bios_uuid network_id network_name aws_owner_id
      #    aws_availability_zone aws_region aws_vpc_id aws_ec2_instance_group_name aws_ec2_instance_state_name
      #    aws_ec2_instance_type aws_subnet_id aws_ec2_product_code aws_ec2_name mcafee_epo_guid mcafee_epo_agent_guid
      #    servicenow_sysid bigfix_asset_id agent_names installed_software ipv4s ipv6s fqdns mac_addresses
      #    netbios_names operating_systems system_types hostnames ssh_fingerprints qualys_asset_ids qualys_host_ids
      #    manufacturer_tpm_ids symantec_ep_hardware_keys sources tags network_interfaces]

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

      def get_request(url)
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        request = Net::HTTP::Get.new(url, 'x-apikeys' => "accessKey=#{ACCESS_KEY};secretKey=#{SECRET_KEY}",
                                          'accept' => 'application/json')
        response = http.request(request)
        unless response.code == '200'
          ap response.body
          raise "Failed! #{response.code}"
        end
        JSON.parse(response.body)
      end

      def post_request(url, json)
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        request = Net::HTTP::Post.new(url, 'x-apikeys' => "accessKey=#{ACCESS_KEY};secretKey=#{SECRET_KEY}",
                                           'accept' => 'application/json', 'content-type' => 'application/json')
        request.body = json.to_json
        response = http.request(request)
        unless response.code == '200'
          ap response.body
          raise "Failed! #{response.code}"
        end

        JSON.parse(response.body)
      end

      def retrieve_assets
        url = URI('https://cloud.tenable.com/assets')
        assets = retrieve_assets_internal(url)
        ingest_assets(assets)
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

      def retrieve_asset_vulns(plugin_id = 51_192, plugin = nil)
        # url = URI('https://cloud.tenable.com/workbenches/assets/f678a680-aced-4412-8dec-164e639ccbc5/vulnerabilities')
        url = URI("https://cloud.tenable.com/workbenches/vulnerabilities/#{plugin_id}/outputs")
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        vulnerability = plugin || Vulnerability.find_by!(external: plugin_id)
        vulns = retrieve_asset_vulns_internal(http, url, vulnerability)
        ingest_asset_vulns(vulns)
      end

      def retrieve_assets_internal(url)
        body = get_request(url)
        assets = body['assets'].collect { |asset| map_asset(asset) }
        assets.collect { |asset| Asset.new(asset) }
      end

      def map_bulk_vulns(body)
        body.collect do |vuln|
          { external: vuln['asset']['uuid'], fqdn: vuln['asset']['fqdn'], netbios_name: vuln['asset']['netbios_name'],
            ipv4: vuln['asset']['ipv4'], operating_system: vuln['asset']['operating_system']&.first,
            plugin_id: vuln['plugin']['id'], severity: vuln['severity'], state: vuln['state'],
            first_seen: vuln['first_found'], last_seen: vuln['last_found'] }
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

      def ingest_assets(assets)
        Asset.import assets, validate: true
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

      def obtain_related_plugins(body)
        plugin_ids = body.collect { |x| x['plugin']['id'] }.uniq
        Vulnerability.where(external: plugin_ids)
      end

      def asset_vulns_plugins_to_records(vulns, asset_ids, plugins)
        assets = Asset.where(external: asset_ids)
        vulns.collect do |asset_vuln|
          found_asset = assets.detect { |a2| a2.external == asset_vuln[:external] }
          puts "Asset not found: #{asset_vuln[:external]}" unless found_asset
          found_plugin = plugins.detect { |plugin| plugin.external == asset_vuln[:plugin_id] }
          puts "Plugin not found: #{asset_vuln[:plugin_id]}" unless found_plugin
          attrs = asset_vuln.merge(asset_id: found_asset&.id, vulnerability_id: found_plugin&.id).except(:plugin_id)
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
