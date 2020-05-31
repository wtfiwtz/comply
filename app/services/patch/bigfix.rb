# frozen_string_literal: true

require 'amazing_print'

module Patch
  # Bigfix importer service
  class Bigfix
    BIGFIX_SERVER = ''
    BIGFIX_PORT = 52_311
    BASIC_AUTH_USERNAME = ''
    BASIC_AUTH_PASSWORD = ''
    VERIFY_CERTIFICATE = false

    class << self
      def import_computers
        url = URI("https://#{BIGFIX_SERVER}:#{BIGFIX_PORT}/api/computers")
        doc = get_request(url)
        computers = []
        doc.xpath('//BESAPI/Computer').each do |computer|
          id = computer.xpath('ID').first&.content
          resource = computer['Resource']
          last_time = computer.xpath('LastReportTime').first&.content
          computers.push(id: id, last_report_time: last_time, resource: resource)
        end
        computers
      end

      def import_computer(computer)
        url = URI("https://#{BIGFIX_SERVER}:#{BIGFIX_PORT}/api/computer/#{computer}")
        doc = get_request(url)
        result = collect_properties(doc)
        { id: computer, properties: result,
          resource: "https://#{BIGFIX_SERVER}:#{BIGFIX_PORT}/api/computer/#{computer}" }
      end

      private

      def get_request(url)
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        http.verify_mode = VERIFY_CERTIFICATE ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        request = Net::HTTP::Get.new(url)
        request.basic_auth(BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD)
        response = http.request(request)
        raise "Failed! #{response.code}\n#{response.body}" unless response.code == '200'

        Nokogiri::XML(response.body)
      end

      def collect_properties(doc)
        properties = []
        doc.xpath('//BESAPI/Computer/Property').each do |property|
          properties.push(key: property['Name'], value: property.content)
        end
        properties.each_with_object({}) do |ele, ary|
          ary[ele[:key]] ||= []
          ary[ele[:key]].push(ele[:value])
          ary
        end
      end
    end
  end
end
