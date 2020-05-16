# frozen_string_literal: true

# Rails migration
class CreateAssetVulnerabilities < ActiveRecord::Migration[6.0]
  # rubocop:disable Metrics/MethodLength
  def change
    create_table :asset_vulnerabilities do |t|
      t.references :asset, null: false, foreign_key: true
      t.references :vulnerability, null: false, foreign_key: true
      t.string :external
      t.string :hostname
      t.string :ipv4
      t.string :netbios_name
      t.text :fqdn
      t.datetime :first_seen
      t.datetime :last_seen

      t.timestamps
    end
  end
end
