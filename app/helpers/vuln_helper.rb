module VulnHelper
  def severity_to_colour(severity_id)
    case severity_id
    when 4 then 'purple'
    when 3 then 'red'
    when 2 then 'orange'
    when 1 then 'green'
    when 0 then 'blue'
    else 'gray'
    end
  end

  def show_severity_counts(asset)
    severities = asset.count_by_severity
    str = ''
    str = append_severity(str, severities, 'critical')
    str = append_severity(str, severities, 'high')
    str = append_severity(str, severities, 'medium')
    str = append_severity(str, severities, 'low')
    str = append_severity(str, severities, 'info')
    str
  end

  def append_severity(str, hsh, kind)
    return str unless hsh[kind]&.positive?

    str += '; ' if str.present?
    "#{str}#{hsh[kind]} #{kind}"
  end
end
