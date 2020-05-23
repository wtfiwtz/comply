class VulnController < ApplicationController
  def index
    @assets = Asset.joins(:asset_vulnerabilities).includes(:asset_vulnerabilities) \
                   .order('COUNT(vulnerability_id) DESC').group('asset_id').limit(50)
  end

  def show
    @asset = Asset.joins(asset_vulnerabilities: :vulnerability) \
                  .order('vulnerabilities.severity_id' => :desc).find(params[:id])
  end
end
