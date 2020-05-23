# frozen_string_literal: true

# Vulnerability Controller class
class VulnController < ApplicationController
  def index
    @merged_counts = obtain_merged_counts
    @assets = Asset.joins(:asset_vulnerabilities).includes(:asset_vulnerabilities) \
                   .select('COUNT(vulnerability_id) AS vuln_count').order('COUNT(vulnerability_id) DESC') \
                   .group(:asset_id, 'asset_vulnerabilities.severity').limit(50)
  end

  def show
    @asset = Asset.joins(asset_vulnerabilities: :vulnerability) \
                  .order('vulnerabilities.severity_id' => :desc).find(params[:id])
  end

  private

  def obtain_merged_counts
    counted_assets = Asset.joins(:asset_vulnerabilities) \
                          .select('assets.id, asset_vulnerabilities.severity, COUNT(vulnerability_id) AS cnt') \
                          .order('COUNT(vulnerability_id) DESC, asset_vulnerabilities.severity DESC') \
                          .group('assets.id, asset_vulnerabilities.severity')
    asset_counts = counts_to_array(counted_assets)
    counts_array_to_hash(asset_counts)
  end

  def counts_to_array(counted_assets)
    counted_assets.collect do |asset|
      { asset.id => { asset.attributes['severity'] => asset.attributes['cnt'] } }
    end
  end

  def counts_array_to_hash(asset_counts)
    asset_counts.each_with_object({}) do |e, a|
      a[e.first[0]] ||= {}
      a[e.first[0]].merge!(e.first[1])
      a
    end
  end
end
