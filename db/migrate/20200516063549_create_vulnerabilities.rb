# frozen_string_literal: true

# Rails migration
class CreateVulnerabilities < ActiveRecord::Migration[6.0]
  def change
    create_table :vulnerabilities do |t|
      t.integer :external
      t.string :name
      t.string :state
      t.string :severity

      t.timestamps
    end
  end
end
