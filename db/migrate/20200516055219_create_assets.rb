# frozen_string_literal: true

# Rails migration
class CreateAssets < ActiveRecord::Migration[6.0]
  def change
    create_table :assets do |t|
      t.string :external
      t.text :fqdn
      t.string :netbios_name
      t.string :operating_system
      t.string :last_ipv4
      t.string :last_ipv6

      t.timestamps
    end
  end
end
