# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `rails
# db:schema:load`. When creating a new database, `rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema.define(version: 2020_05_17_095300) do

  create_table "asset_vulnerabilities", force: :cascade do |t|
    t.integer "asset_id", null: false
    t.integer "vulnerability_id", null: false
    t.string "external"
    t.string "hostname"
    t.string "ipv4"
    t.string "netbios_name"
    t.string "operating_system"
    t.string "severity"
    t.string "state"
    t.text "fqdn"
    t.datetime "first_seen"
    t.datetime "last_seen"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.index ["asset_id"], name: "index_asset_vulnerabilities_on_asset_id"
    t.index ["vulnerability_id"], name: "index_asset_vulnerabilities_on_vulnerability_id"
  end

  create_table "assets", force: :cascade do |t|
    t.string "external"
    t.text "fqdn"
    t.string "netbios_name"
    t.string "operating_system"
    t.string "last_ipv4"
    t.string "last_ipv6"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
  end

  create_table "vulnerabilities", force: :cascade do |t|
    t.integer "external"
    t.string "name"
    t.string "state"
    t.string "severity"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.integer "severity_id"
  end

  add_foreign_key "asset_vulnerabilities", "assets"
  add_foreign_key "asset_vulnerabilities", "vulnerabilities"
end
