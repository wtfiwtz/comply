# frozen_string_literal: true

# Vuln module
module Vuln
  # TenableAssets concern
  module TenableAssets
    extend ActiveSupport::Concern

    # Class methods in concern
    module ClassMethods
      def retrieve_asset_chunk_status(uuid)
        url = URI("https://cloud.tenable.com/assets/export/#{uuid}/status")
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

      def retrieve_assets
        url = URI('https://cloud.tenable.com/assets')
        assets = retrieve_assets_internal(url)
        ingest_assets(assets)
      end

      def retrieve_assets_internal(url)
        body = get_request(url)
        assets = body['assets'].collect { |asset| map_asset(asset) }
        assets.collect { |asset| Asset.new(asset) }
      end

      def ingest_assets(assets)
        Asset.import assets, validate: true
      end
    end
  end
end
