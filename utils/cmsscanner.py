from vuln_db import cms_vulns as vuln_scan
from colorama import Fore
from bs4 import BeautifulSoup
from plugins import agent_list
from utils import techscanner
import requests
import re
import urllib3

requests.packages.urllib3.disable_warnings()

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

CMS = []

# Check for Wordpress

wordpress_links = ["/wp-login", "/wp-admin", "/wp-login.php", "/wp-admin.php", "/wp-content"]
xml_files = ['administrator/manifests/files/joomla.xml','language/en-GB/en-GB.xml','administrator/components/com_content/content.xml','administrator/components/com_plugins/plugins.xml','administrator/components/com_media/media.xml','mambots/content/moscode.xml']

def Wp(url: str) -> str:
    wp = []
    wp_readme = []
    wp_meta = []
    for wp_links in wordpress_links:
        wordpress = requests.get(f"{url}{wp_links}", verify=False, headers=header)
        if wordpress.status_code == 200:
            wp.append(wp_links)
    sessions = requests.Session()
    wordpress2 = sessions.get(f"{url}/readme.html", verify=False,  headers=header)
    if wordpress2.status_code == 200 and "Wordpress" in wordpress.text:
        wp_readme.append(f"{url}/readme.html")
    wordpress3 = sessions.get(f"{url}", verify=False, headers=header)
    if wordpress3.status_code == 200 and "Wordpress" in wordpress.text:
        soup = BeautifulSoup(wordpress3.content, 'html.parser')
        meta_tag = soup.find_all("meta")
        if "Wordpress" in meta_tag:
            wp_meta.append(meta_tag)
        gen = soup.find_all("meta", attrs={'name':'generator'})
        if gen is None:
            pass
        else:
            print(gen[0].get_text())
    if wp or wp_readme or wp_meta:
        CMS.append("Wordpress")
        vuln_scan.apache_vuln_scan(url)
        vuln_scan.wordpress_vuln_scan(url)
        s = requests.Session()
        xmlrpc_file = s.get(f"{url}/xmlrpc.php", verify=False, headers=header)
        if xmlrpc_file.status_code == 200:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XMLRPC: {Fore.GREEN}{url}/xmlrpc")
        else:
            pass
    if wp:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} WP Directories: {Fore.GREEN}{', '.join(map(str,wp))}")

# Check for Joomla

def Joomla(url: str) -> str:
    try:
        joomla = []
        joomla_readme = []
        joomla_meta = []
        joomla_header_hint = []
        sessions = requests.Session()
        joomscan = sessions.get(f"{url}/administrator", verify=False, headers=header)
        if joomscan.status_code == 200 and "Joomla" in joomscan.text and "404" not in joomscan.text:
            joomla.append(f"{url}/administrator")
        soup = BeautifulSoup(joomscan.content, 'html.parser')
        meta_tag = soup.find_all("meta")
        if "Joomla!" in meta_tag:
            joomla_meta.append(meta_tag)
        joomscan2 =  sessions.get(f"{url}/README.txt", verify=False, headers=header)
        if joomscan2.status_code == 200 and "Joomla!" in joomscan2.text and "404" not in joomscan2.text:
            joomla_readme.append(f"{url}/README.txt")
        joomscan3 = sessions.get(f"{url}", verify=False, headers=header)
        for item, key in joomscan3.headers.items():
            if "Wed, 17 Aug 2005 00:00:00 GMT" in key:
                joomla_header_hint.append(f"{item}:{key}")
        joomscan_version = sessions.get(f"{url}", verify=False, headers=header)
        regex_1 = re.findall(r'content=(?:\"|\')Joomla! (.*?) - Open Source Content Management(?:\"|\')', joomscan_version.text)
        if regex_1 != []:
            CMS.append(f"Joomla {regex_1[0]}")
        else:
            pass
        if joomla or joomla_readme or joomla_meta or joomla_header_hint:
            CMS.append("Joomla")
            vuln_scan.joomla_vuln_scan(url)
    except requests.exceptions.ConnectionError:
        pass

def Drupal(url: str) -> str:
    drupal = []
    drupal_dir = ["/user/", "/user/password/", "/user/register/"]
    sessions = requests.Session()
    drupalscan = sessions.get(f"{url}", verify=False, headers=header)
    if drupalscan.status_code == 200 and "Drupal" in drupalscan.text and "404" not in drupalscan.text:
        drupal.append("Drupal")
    for links in drupal_dir:
        drupalscan2= sessions.get(f"{url}{links}", verify=False, headers=header)
        if drupalscan2.status_code == 200 and "Drupal" in drupalscan2.text:
            drupal.append("Drupal")
    if drupal:
        CMS.append("Drupal")
        vuln_scan.drupal_vuln_scan(url)

def Umbraco(url: str) -> str:
    umbraco = []
    umbraco_dir = "/umbraco"
    sessions = requests.Session()
    umbracoscan = sessions.get(f"{url}{umbraco_dir}", verify=False, headers=header)
    if umbracoscan.status_code == 200 and "var Umbraco" in umbracoscan.text and "404" not in umbracoscan.text:
        umbraco.append("Umbraco")
    if umbraco:
        CMS.append("Umbraco")
        vuln_scan.umbraco_vuln_scan(url)

def Jira(url: str) -> str:
    jira = []
    jira_subdomain = []
    jira_dashboard = []
    jira_main = []
    try:
        sessions = requests.Session()
        jirascan = sessions.get(f"{url}/jira", verify=False, headers=header)
        if jirascan.status_code == 200 and "Jira" in jirascan.text and "404" not in jirascan.text:
            jira.append("Jira")
        split_url = url.split(".")
        split_url.insert(1, "jira")
        split_url = ".".join(split_url)
        if "https://www." in split_url:
            split_url = split_url.replace("www.", "")
        if "http://www." in split_url:
            split_url = split_url.replace("www.", "")
        jirascan2 = sessions.get(f"{split_url}", verify=False, headers=header)
        if jirascan2.status_code == 200:
            jira_subdomain.append("Jira")
        jirascan3 = sessions.get(f"{split_url}/secure/Dashboard.jspa", verify=False, headers=header)
        if jirascan3 == 200 and "404" not in jirascan3.text:
            jira_dashboard.append("Jira")
        jirascan4 = sessions.get(f"{split_url}/jira", verify=False, headers=header)
        if jirascan4 == 200 and "404" not in jirascan4.text:
            jira_main.append("Jira")
        if jira or jira_subdomain or jira_dashboard or jira_main:
            CMS.append("Jira")
            vuln_scan.jira_vuln_scan(url)
    except requests.exceptions.ConnectionError:
        pass

def Magento(url: str) -> str:
    magento = []
    magento_scan = []
    magentodownloader = []
    magentoinstall = []
    sessions = requests.Session()
    m_scan = sessions.get(f"{url}", verify=False, headers=header)
    if "magento" in m_scan.text or "Magento" in m_scan.text:
        magento_scan.append("Magento")
    magentoscan = sessions.get(f"{url}/magento/admin", verify=False, headers=header)
    if magentoscan.status_code == 200 and "Magento" in magentoscan.text and "404" not in magentoscan.text:
        magento.append("Magento")
    magento_downloader = sessions.get(f"{url}/downloader", verify=False, headers=header)
    if magento_downloader.status_code == 200 and "magento connect login page" in magento_downloader.text and "404" not in magento_downloader.text:
        magentodownloader.append("Magento")
    magento_install = sessions.get(f"{url}/install.php", verify=False, headers=header)
    if magento_install.status_code == 200 and "Magento is already installed" in magento_install.text and "404" not in magento_install.text:
        magento.append("Magento")
    if magento or magentodownloader or magentoinstall:
        CMS.append("Magento")
        vuln_scan.magento_vuln_scan(url)

def PhpBB(url: str) -> str:
    cookies = []
    source = []
    tech = []
    try:
        res = requests.get(url, verify=False, headers=header)
        for item, value in res.headers.items():
            if "phpbb_" in value:
                cookies.append("phpbb")
        res2 = requests.get(url, verify=False, headers=header)
        if "phpBB" in res2.text and "404" not in res2.text:
            source.append("phpbb")
        
        # Use the safer builtwith wrapper function
        technologies = techscanner.safe_builtwith(url)
        if technologies and "phpBB" in str(technologies):
            tech.append("phpBB")
            
        if cookies or source or tech:
            CMS.append("phpBB")
            vuln_scan.phpbb_vuln_scan(url)
    except requests.exceptions.ConnectTimeout:
        pass
    except urllib3.exceptions.MaxRetryError:
        pass
    except UnicodeDecodeError:
        # Handle Unicode decode errors at the function level
        pass
    except Exception as e:
        # Handle any other unexpected errors
        pass

def Shopify(url: str) -> str:
    shopify_name = []
    shopify_endpoint = ["/cart", "/checkout"]
    found_endpoints = []
    meta_tags = []
    js_files = []
    if "shopify" in url:
        shopify_name.append(url)
    for endpoints in shopify_endpoint:
        s = requests.Session()
        res = s.get(f"{url}{endpoints}", verify=False)
        if res.status_code == 200 and "shopify" in res.text and "404" not in res.text:
             found_endpoints.append(f"{url}{endpoints}")
        else:
            pass
    res2 = s.get(f"{url}", verify=False)
    if "shopify.js" in res2.text or "shop.js" in res2.text and "404" not in res2.text:
        js_files.append("shopify javascript files")
    soup = BeautifulSoup(res2.content, 'html.parser')
    meta_tag = soup.find_all("meta")
    if "shopify" in meta_tag or "Shopify" in meta_tag:
        meta_tag.append("Shopify")
    if shopify_name or js_files or found_endpoints or meta_tags:
        CMS.append("Shopify")
        vuln_scan.shopify_vuln_scan(url)

def PrestaShop(url: str) -> str:
    prestashop = []
    sessions = requests.Session()
    
    # Check for PrestaShop admin panel
    admin_url = f"{url}/admin"
    res = sessions.get(admin_url, verify=False, headers=header)
    if res.status_code == 200 and "PrestaShop" in res.text:
        prestashop.append("Admin panel found")

    # Check for specific PrestaShop files
    ps_files = ['/modules/ps_facetedsearch/ps_facetedsearch.php', '/config/smarty.config.inc.php']
    for file in ps_files:
        res = sessions.get(f"{url}{file}", verify=False, headers=header)
        if res.status_code == 200:
            prestashop.append(f"File found: {file}")

    # Check for PrestaShop meta generator tag
    res = sessions.get(url, verify=False, headers=header)
    if 'content="PrestaShop"' in res.text:
        prestashop.append("Meta generator tag found")

    if prestashop:
        CMS.append("PrestaShop")
        vuln_scan.prestashop_vuln_scan(url)

def OpenCart(url: str) -> str:
    opencart = []
    sessions = requests.Session()
    
    # Check for OpenCart admin panel
    admin_url = f"{url}/admin"
    res = sessions.get(admin_url, verify=False, headers=header)
    if res.status_code == 200 and "OpenCart" in res.text:
        opencart.append("Admin panel found")

    # Check for specific OpenCart files
    oc_files = ['/system/startup.php', '/catalog/view/theme/default/stylesheet/stylesheet.css']
    for file in oc_files:
        res = sessions.get(f"{url}{file}", verify=False, headers=header)
        if res.status_code == 200:
            opencart.append(f"File found: {file}")

    # Check for OpenCart specific cookies
    res = sessions.get(url, verify=False, headers=header)
    if 'OCSESSID' in res.cookies:
        opencart.append("OpenCart session cookie found")

    if opencart:
        CMS.append("OpenCart")
        vuln_scan.opencart_vuln_scan(url)

def Wix(url: str) -> str:
    wix = []
    sessions = requests.Session()
    
    res = sessions.get(url, verify=False, headers=header)
    
    # Check for Wix-specific meta tags
    if 'X-Wix-Published-Version' in res.headers:
        wix.append("Wix-specific header found")
    
    # Check for Wix-specific JavaScript
    if 'static.wixstatic.com' in res.text or 'wix.com' in res.text:
        wix.append("Wix-specific JavaScript found")
    
    # Check for Wix-specific HTML comment
    if '<!-- RENDERED BY WIX.COM' in res.text:
        wix.append("Wix-specific HTML comment found")

    if wix:
        CMS.append("Wix")
        vuln_scan.wix_vuln_scan(url)

def Squarespace(url: str) -> str:
    squarespace = []
    sessions = requests.Session()
    
    res = sessions.get(url, verify=False, headers=header)
    
    # Check for Squarespace-specific meta tags
    if 'X-ServedBy: squarespace' in str(res.headers):
        squarespace.append("Squarespace-specific header found")
    
    # Check for Squarespace-specific JavaScript
    if 'static1.squarespace.com' in res.text or 'squarespace.com' in res.text:
        squarespace.append("Squarespace-specific JavaScript found")
    
    # Check for Squarespace-specific HTML comment
    if '<!-- This is Squarespace. -->' in res.text:
        squarespace.append("Squarespace-specific HTML comment found")

    if squarespace:
        CMS.append("Squarespace")
        vuln_scan.squarespace_vuln_scan(url)


def main(url: str) -> str:
    Joomla(url)
    Wp(url)
    Drupal(url)
    Jira(url)
    PhpBB(url)
    Umbraco(url)
    Magento(url)
    Shopify(url)
    PrestaShop(url)
    OpenCart(url)
    Wix(url)        
    Squarespace(url) 
    if CMS:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} CMS: {Fore.GREEN}{Fore.GREEN}{', '.join(map(str,CMS))}")
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} CMS: {Fore.RED}No CMS detected!")
   