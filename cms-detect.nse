-- Define the script's category and description
description = [[
  Detects if a website is using WordPress, Joomla, PrestaShop, Moodle, or MediaWiki by checking:
  - The existence of common files and directories
  - HTTP headers for CMS traces
  - The robots.txt file for CMS-related exclusions
  - Attempts to identify the CMS version by searching for specific files and meta tags
  - Identifies installed themes, plugins, modules, extensions, or libraries by probing common paths
]]

-- Define the script categories
categories = {"discovery", "safe"}

-- Import required modules
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

-- Define the target port (80 or 443 for HTTP/HTTPS)
portrule = shortport.http

-- Function to detect CMS version from meta tag
local function detect_cms_version(body, cms_name)
  local version_patterns = {
    WordPress = '<meta name="generator" content="WordPress (%d+%.%d+%.?%d*)',
    Joomla = '<meta name="generator" content="Joomla! (%d+%.%d+%.?%d*)',
    PrestaShop = '<meta name="generator" content="PrestaShop (%d+%.%d+%.?%d*)',
    MediaWiki = '<meta name="generator" content="MediaWiki (%d+%.%d+%.?%d*)'
  }
  
  local pattern = version_patterns[cms_name]
  if pattern then
    return body:match(pattern)
  end
  return nil
end

-- Function to parse robots.txt for CMS clues
local function check_robots_txt(body)
  if body:match("Disallow: /wp%-admin/") or body:match("Disallow: /wp%-includes/") then
    return "WordPress exclusions found in robots.txt"
  elseif body:match("Disallow: /administrator/") then
    return "Joomla exclusions found in robots.txt"
  elseif body:match("Disallow: /admin/") then
    return "PrestaShop or Moodle exclusions found in robots.txt"
  elseif body:match("Disallow: /w/") or body:match("Disallow: /wiki/") then
    return "MediaWiki exclusions found in robots.txt"
  end
  return nil
end

-- Function to parse HTTP headers for CMS clues
local function check_http_headers(headers)
  for name, value in pairs(headers) do
    if value:match("wp%-admin") or value:match("WordPress") then
      return "HTTP header suggests WordPress: " .. name .. ": " .. value
    elseif value:match("Joomla") then
      return "HTTP header suggests Joomla: " .. name .. ": " .. value
    elseif value:match("PrestaShop") then
      return "HTTP header suggests PrestaShop: " .. name .. ": " .. value
    elseif value:match("Moodle") then
      return "HTTP header suggests Moodle: " .. name .. ": " .. value
    elseif value:match("MediaWiki") then
      return "HTTP header suggests MediaWiki: " .. name .. ": " .. value
    end
  end
  return nil
end

-- Function to check for WordPress themes
local function check_wp_themes(host, port)
  local themes_result = {}
  local themes_path = "/wp-content/themes/"
  local response = http.get(host, port, themes_path)

  if response and response.status == 200 then
    table.insert(themes_result, "Possible WordPress themes directory found: /wp-content/themes/")
  end

  return themes_result
end

-- Function to check for WordPress plugins
local function check_wp_plugins(host, port)
  local plugins_result = {}
  local plugins_path = "/wp-content/plugins/"
  local response = http.get(host, port, plugins_path)

  if response and response.status == 200 then
    table.insert(plugins_result, "Possible WordPress plugins directory found: /wp-content/plugins/")
  end

  return plugins_result
end

-- Function to check for Joomla components
local function check_joomla_components(host, port)
  local components_result = {}
  local components_path = "/components/"
  local response = http.get(host, port, components_path)

  if response and response.status == 200 then
    table.insert(components_result, "Possible Joomla components directory found: /components/")
  end

  return components_result
end

-- Function to check for PrestaShop modules
local function check_prestashop_modules(host, port)
  local modules_result = {}
  local modules_path = "/modules/"
  local response = http.get(host, port, modules_path)

  if response and response.status == 200 then
    table.insert(modules_result, "Possible PrestaShop modules directory found: /modules/")
  end

  return modules_result
end

-- Function to check for Moodle libraries
local function check_moodle_libs(host, port)
  local libs_result = {}
  local libs_path = "/lib/"
  local response = http.get(host, port, libs_path)

  if response and response.status == 200 then
    table.insert(libs_result, "Possible Moodle libraries directory found: /lib/")
  end

  return libs_result
end

-- Function to check for MediaWiki directories
local function check_mediawiki_paths(host, port)
  local mediawiki_result = {}
  local paths = {"/w/", "/wiki/", "/api.php"}

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(mediawiki_result, "Possible MediaWiki directory or file found: " .. path)
    end
  end

  return mediawiki_result
end

-- Function to check other version files
local function check_other_version_files(host, port, cms_name)
  local version_files = {
    WordPress = {"/wp-links-opml.php", "/license.txt"},
    Joomla = {"/administrator/manifests/files/joomla.xml"},
    PrestaShop = {"/admin/dashboard", "/README.md"},
    Moodle = {"/version.php", "/README.txt"},
    MediaWiki = {"/api.php?action=query&meta=siteinfo&siprop=general"}
  }
  
  local version_result = {}
  local files_to_check = version_files[cms_name] or {}

  for _, path in ipairs(files_to_check) do
    local response = http.get(host, port, path)

    if response and response.status == 200 then
      local version = response.body:match(cms_name .. " (%d+%.%d+%.?%d*)")
      if version then
        table.insert(version_result, cms_name .. " version detected from " .. path .. ": " .. version)
      else
        table.insert(version_result, path .. " found, but version could not be detected.")
      end
    end
  end

  return version_result
end

-- Main function of the script
action = function(host, port)
  local results = {}
  
  -- WordPress detection
  local wp_login_path = "/wp-login.php"
  local wp_login_response = http.get(host, port, wp_login_path)
  
  if wp_login_response and (wp_login_response.status == 200 or wp_login_response.status == 301) then
    table.insert(results, "Found: /wp-login.php (WordPress)")
  end

  -- Joomla detection
  local joomla_admin_path = "/administrator/"
  local joomla_admin_response = http.get(host, port, joomla_admin_path)

  if joomla_admin_response and (joomla_admin_response.status == 200 or joomla_admin_response.status == 301) then
    table.insert(results, "Found: /administrator/ (Joomla)")
  end

  -- PrestaShop detection
  local prestashop_admin_path = "/admin/"
  local prestashop_admin_response = http.get(host, port, prestashop_admin_path)

  if prestashop_admin_response and (prestashop_admin_response.status == 200 or prestashop_admin_response.status == 301) then
    table.insert(results, "Found: /admin/ (PrestaShop or Moodle)")
  end

  -- Moodle detection
  local moodle_lib_path = "/lib/"
  local moodle_lib_response = http.get(host, port, moodle_lib_path)

  if moodle_lib_response and (moodle_lib_response.status == 200 or moodle_lib_response.status == 301) then
    table.insert(results, "Found: /lib/ (Moodle)")
  end

  -- MediaWiki detection
  local mediawiki_paths = check_mediawiki_paths(host, port)
  for _, path_result in ipairs(mediawiki_paths) do
    table.insert(results, path_result)
  end

  -- Check HTTP headers for CMS traces
  local index_response = http.get(host, port, "/")
  if index_response and index_response.status == 200 then
    local header_result = check_http_headers(index_response.header)
    if header_result then
      table.insert(results, header_result)
    end

    -- Detect versions via meta tags
    local wp_version = detect_cms_version(index_response.body, "WordPress")
    if wp_version then
      table.insert(results, "WordPress version detected from meta tag: " .. wp_version)
    end

    local joomla_version = detect_cms_version(index_response.body, "Joomla")
    if joomla_version then
      table.insert(results, "Joomla version detected from meta tag: " .. joomla_version)
    end

    local prestashop_version = detect_cms_version(index_response.body, "PrestaShop")
    if prestashop_version then
      table.insert(results, "PrestaShop version detected from meta tag: " .. prestashop_version)
    end

    local mediawiki_version = detect_cms_version(index_response.body, "MediaWiki")
    if mediawiki_version then
      table.insert(results, "MediaWiki version detected from meta tag: " .. mediawiki_version)
    end
  end

  -- Check other version files
  local wp_version_files = check_other_version_files(host, port, "WordPress")
  for _, v in ipairs(wp_version_files) do table.insert(results, v) end

  local joomla_version_files = check_other_version_files(host, port, "Joomla")
  for _, v in ipairs(joomla_version_files) do table.insert(results, v) end

  local prestashop_version_files = check_other_version_files(host, port, "PrestaShop")
  for _, v in ipairs(prestashop_version_files) do table.insert(results, v) end

  local moodle_version_files = check_other_version_files(host, port, "Moodle")
  for _, v in ipairs(moodle_version_files) do table.insert(results, v) end

  local mediawiki_version_files = check_other_version_files(host, port, "MediaWiki")
  for _, v in ipairs(mediawiki_version_files) do table.insert(results, v) end

  -- Return results if anything was found
  if #results > 0 then
    return stdnse.format_output(true, results)
  else
    return "No CMS detected (WordPress, Joomla, PrestaShop, Moodle, or MediaWiki)."
  end
end

