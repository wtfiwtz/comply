class AddSeverityIdToVulnerabilities < ActiveRecord::Migration[6.0]
  def change
    add_column :vulnerabilities, :severity_id, :integer
  end
end
