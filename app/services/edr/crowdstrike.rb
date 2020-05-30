# frozen_string_literal: true

require 'amazing_print'
require 'oauth2'

# crowdstrike = Edr::Crowdstrike.new
# asset_ids = crowdstrike.asset_ids
# assets = crowdstrike.assets(asset_ids)
# crowdstrike.ingest_assets(crowdstrike.map_assets(assets))

module Edr
  # Crowdstrike importer service
  class Crowdstrike
    # https://assets.falcon.crowdstrike.com/support/api/swagger.html#/
    # https://falcon.crowdstrike.com/support/api-clients-and-keys
    # https://falcon.crowdstrike.com/support/documentation/46/crowdstrike-oauth2-based-apis
    CLIENT_ID = ''
    CLIENT_SECRET = ''
    # ENV['OAUTH_DEBUG'] == 'true'

    def retrieve_access_token
      # Faraday::Utils.default_params_encoder = Faraday::NestedParamsEncoder
      @client = OAuth2::Client.new(CLIENT_ID, CLIENT_SECRET, site: 'https://api.crowdstrike.com',
                                                             token_url: '/oauth2/token', auth_scheme: :basic_auth)
      @token = @client.client_credentials.get_token
    end

    def asset_ids
      @token ||= retrieve_access_token
      response = @token.get('/devices/queries/devices/v1', params: { limit: 10 })
      raise "Error! #{response.status}" unless response.status == 200

      json = JSON.parse(response.body)
      json['resources']
    end

    def assets(asset_ids)
      @token ||= retrieve_access_token
      response = @token.get('/devices/entities/devices/v1', params: { ids: asset_ids }) do |req|
        req.options.update(params_encoder: Faraday::FlatParamsEncoder)
      end
      raise "Error! #{response.status}" unless response.status == 200

      json = JSON.parse(response.body)
      json['resources']
    end

    # "device_id" => "xxx",
    #     "cid" => "yyy",
    #     "agent_load_flags" => "0",
    #     "agent_local_time" => "2020-05-16T11:40:10.428Z",
    #     "agent_version" => "5.31.11304.0",
    #     "bios_manufacturer" => "American Megatrends Inc.",
    #     "bios_version" => "090006 ",
    #     "build_number" => "7601",
    #     "config_id_base" => "65994753",
    #     "config_id_build" => "11304",
    #     "config_id_platform" => "3",
    #     "external_ip" => "xxx.xxx.xxx.xxx",
    #     "mac_address" => "00-15-5d-xx-xx-xx",
    #     "hostname" => "HOSTNAME",
    #     "first_seen" => "2018-11-23T17:30:39Z",
    #     "last_seen" => "2020-05-23T07:18:21Z",
    #     "local_ip" => "xxx.xxx.xxx.xxx",
    #     "machine_domain" => "domain.local",
    #     "major_version" => "6",
    #     "minor_version" => "1",
    #     "os_version" => "Windows Server 2008 R2",
    #     "ou" => [

    def map_assets(assets)
      assets.collect do |asset|
        attrs = { external: asset['device_id'], last_ipv4: asset['local_ip'], netbios_name: asset['hostname'],
                  operating_system: asset['os_version'] }
        Asset.new(attrs)
      end
    end

    def ingest_assets(assets)
      Asset.import assets, validate: true
    end
  end
end
