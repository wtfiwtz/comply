# frozen_string_literal: true

# Rails model
class Asset < ApplicationRecord
  has_many :asset_vulnerabilities
  has_many :vulnerabilities, through: :asset_vulnerabilities

  def count_by_severity
    asset_vulnerabilities.group(:severity).count
  end
end
