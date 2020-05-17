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
# set = AssetVulnerability.group(:asset_id).count
# set.sort_by { |k,v| -v }

module Vuln
  # Tenable importer service
  class Tenable
    include TenableAssets
    include TenableVulns
    include TenableMappings

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

      private

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
        raise "Failed POST request! #{response.code}; #{JSON.parse(response.body)}" unless response.code == '200'

        JSON.parse(response.body)
      end
    end
  end
end
