# frozen_string_literal: true

# Rails model
class Asset < ApplicationRecord
  has_many :asset_vulnerabilities
end
