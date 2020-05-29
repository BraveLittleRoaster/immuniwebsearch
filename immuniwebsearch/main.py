import os
import sys
import csv
import time
import json
import argparse
from bs4 import BeautifulSoup
from selenium import webdriver
from multiprocessing import Pool
from immuniwebsearch.setup_logger import *
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC
from tenacity import retry, retry_if_exception_type, wait_random, stop_after_attempt
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException


class RetryException(Exception):

    def __init__(self):

        pass


class Scraper:

    def __init__(self, **kwargs):

        self.proxy = kwargs.get('proxy')
        self._csv_out = kwargs.get('csv_out')
        self._json_out = kwargs.get('json_out')
        self._x = kwargs.get('x')

        self._base_url = "https://www.immuniweb.com/radar/"

    @staticmethod
    def parse_phish(element):
        # TODO: Add support for other threat intel options.
        pass

    @staticmethod
    def parse_squats(element, search_domain, type):

        all_results = []

        for row in element.find_all("tr", {"class": "mutator_true row_score row_score_"}):

            # Extract domain information

            domains = [
                row.find("span", {"class": "pull-left label label-part-of-url http full-width-mutator status_active mutation-malicious"}),
                row.find("span", {"class": "pull-left label label-part-of-url http full-width-mutator status_inactive mutation-malicious"}),
                row.find("span", {"class": "pull-left label label-part-of-url http full-width-mutator status_active mutation-legitimate"}),
                row.find("span", {"class": "pull-left label label-part-of-url http full-width-mutator status_inactive mutation-legitimate"}),
            ]
            domain = None
            for dom in domains:
                if dom:
                    domain = dom.text.replace(" ", "")

            if domain is None:
                logger.warning(f"Unknown domain type @ {type}: {search_domain}")
                return False
            # Extract server information
            server_info = row.find("div", {"class": "vcenter"})
            has_webserver = False
            has_exchange = False
            webserver = server_info.find("i", {"class": "fa fa-globe"})
            ex_server = server_info.find("i", {"class": "fa fa-envelope"})
            if webserver:
                has_webserver = True
            if ex_server:
                has_exchange = True

            # Extract Geolocation country code
            cc = row.find("span", {"class": "pull-left label label-info countrycode"})
            if cc:
                cc = cc.get("data-content")

            # Extract IP information
            ip = row.find("span", {"class": "label label-gray pull-left"})
            if ip:
                ip = ip.text

            # Extract registry information, the 'created' column is just the registry date in the mouse-over event.
            registry_info = {}
            registry = row.find("span", {"class": "label label-gray registrar_popover"})
            if registry:
                registry = registry.get("data-content")
                registry = registry.split("<br>")
                for subkey in registry:
                    key = subkey.split(":")[0]
                    value = subkey.split(":")[1]
                    registry_info[key] = value

            result = {
                "domain": domain,
                "country_code": cc,
                "ip": ip,
                "web_server": has_webserver,
                "email_server": has_exchange,
                "registry_info": registry_info
            }
            all_results.append(result)

            logger.debug(f"Found result for search: {result}")
        if all_results:
            logger.log(LVL.SUCCESS, f"Extracted a total of {len(all_results)} {type} domains for {search_domain}.")
        else:
            logger.warning(f"Found no results for {type} domains for {search_domain}.")
        return all_results

    @retry(retry=retry_if_exception_type(RetryException), wait=wait_random(10, 60), stop=stop_after_attempt(3))
    def domain_search(self, domain):

        logger.info(f"Searching {domain} @ {self._base_url}...")

        if self.proxy:
            logger.debug(f"Using proxy: {self.proxy}")
            PROXY_PROTO = self.proxy.split(":")[0].lower()
            PROXY_HOST = self.proxy.split(":")[1].replace("/", "")
            PROXY_PORT = int(self.proxy.split(":")[2])
            fp = webdriver.FirefoxProfile()

            if PROXY_PROTO == "socks4" or PROXY_PROTO == "socks5":
                fp.set_preference("network.proxy.type", 1)
                fp.set_preference("network.proxy.socks", PROXY_HOST)
                fp.set_preference("network.proxy.socks_port", PROXY_PORT)
            else:
                fp.set_preference("network.proxy.type", 1)
                fp.set_preference("network.proxy.http", PROXY_HOST)
                fp.set_preference("network.proxy.http_port", PROXY_PORT)
                fp.set_preference("network.proxy.https", PROXY_HOST)
                fp.set_preference("network.proxy.https_port", PROXY_PORT)
                fp.set_preference("network.proxy.ssl", PROXY_HOST)
                fp.set_preference("network.proxy.ssl_port", PROXY_PORT)
                fp.set_preference("network.proxy.ftp", PROXY_HOST)
                fp.set_preference("network.proxy.ftp_port", PROXY_PORT)
            # Create the driver with proxy support.
            driver = webdriver.Firefox(firefox_profile=fp)
        else:
            driver = webdriver.Firefox()

        driver.get(self._base_url)

        try:
            search_box = WebDriverWait(driver, 20).until(
                EC.element_to_be_clickable((By.ID, "phishsearch-domain"))
            )
        except UnexpectedAlertPresentException as e:
            logger.info("[!] ERROR: Failed to connect to proxy: {e}")
            return None
        search_box.click()

        search_box.send_keys(domain)
        search_box.send_keys(Keys.ENTER)
        try:
            cybersquat = WebDriverWait(driver, 30).until(
                EC.element_to_be_clickable((By.ID, "potential-cybersquatting"))
            )
            typosquat = WebDriverWait(driver, 30).until(
                EC.element_to_be_clickable((By.ID, "potential-typosquatting"))
            )
            phishing_container = WebDriverWait(driver, 30).until(
                EC.element_to_be_clickable((By.ID, "phishing-container"))
            )
            social_networks = WebDriverWait(driver, 30).until(
                EC.element_to_be_clickable((By.ID, "social-networks"))
            )
        except TimeoutException as e:
            logger.error(f"Could not find the elements. Proxy issue? {e}")
            raise RetryException

        try:
            cyber_expand = WebDriverWait(driver, 3).until(
                EC.element_to_be_clickable((By.XPATH, "/html/body/div[3]/main/div[3]/div[5]/div/div[3]/div[2]/div[1]/div[2]/div/div/i"))
            )
            typo_expand = WebDriverWait(driver, 3).until(
                EC.element_to_be_clickable((By.XPATH, "/html/body/div[3]/main/div[3]/div[5]/div/div[4]/div[2]/div[1]/div[2]/div/div/i"))
            )
        except TimeoutException as e:
            logger.warning(f"Could not find expansion button for {domain}. Likely a locked IP. Retrying the request...")
            if not self._x:
                driver.close()
            raise RetryException

        cyber_expand.click()
        time.sleep(10)  # Wait for list to load
        typo_expand.click()
        time.sleep(10)  # Wait for list to load
        logger.debug(f"Waiting 20 seconds for results to load for search: {domain}")
        cur_url = driver.current_url
        search_id = cur_url.split("=")[1]  # strip the ID off
        if search_id:
            logger.debug(f"Got our id: {search_id}")
        html = driver.page_source
        logger.debug(f"Closing Selenium driver for search: {domain}.")
        if self._x:
            logger.debug(f"Keeping webdriver open for search: {domain}!")
        else:
            driver.close()

        all_results = {
            "search_id": search_id,
            "results": []
        }

        soup = BeautifulSoup(html, "html.parser")
        cybersquat_t = soup.find("table", {"id": "results4"})
        typosquat_t = soup.find("table", {"id": "results2"})
        potential_phish = soup.find("div", {"id", "search-block1"})

        if potential_phish.find("div", {"class": "new-alert__description"}).text == "No phishing websites found":
            logger.debug("Found no potential phishing websites for {domain}.")
            phish_results = []
        else:
            phish_results = self.parse_phish(potential_phish)
        cyber_results = self.parse_squats(cybersquat_t, domain, "CyberSquatting")
        typo_results = self.parse_squats(typosquat_t, domain, "TypoSquatting")

        for row in cyber_results:
            all_results['results'].append(row)
        for row in typo_results:
            all_results['results'].append(row)

        return all_results

    def dump_csv(self, all_results):

        fieldnames = [
            "domain",
            "country_code",
            "ip",
            "web_server",
            "email_server",
            "registry_info"
        ]
        logger.info("Dumping results to csv...")
        with open(self._csv_out, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in all_results:
                results = result.get("results")
                for row in results:
                    writer.writerow(row)

        csvfile.close()

    def dump_json(self, all_results):

        ts = time.gmtime()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", ts)

        results = {
            "timestamp": timestamp,
            "all_results": all_results
        }
        logger.info("Dumping results to json...")
        with open(self._json_out, 'w') as jsonfile:

            jsonfile.write(json.dumps(results, sort_keys=True, indent=4))

        jsonfile.close()

    def run(self, input_list):
        # TODO: Add support for -iL option to scan a list of domains.
        p = Pool()
        with open(input_list, 'r') as f:
            domains_raw = f.readlines()

        domains = []
        for domain in domains_raw:
            # Trim \r\n or \n off each domain.
            domain.rstrip("\n")
            domain.rstrip("\r")
            domains.append(domain)

        f.close()
        all_results = []
        for _ in p.imap_unordered(self.domain_search, domains):
            if _:
                logger.log(LVL.SPAM, _)
                all_results.append(_)

        if self._csv_out:
            self.dump_csv(all_results)
        if self._json_out:
            self.dump_json(all_results)


def which(program):

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

def main():

    parser = argparse.ArgumentParser('Check immuniweb.com for threat intel on the given domain(s).')
    # Switched args
    parser.add_argument("-v", dest="verbose", action='count', default=0, help="Enable verbose output. Ex: -v, -vv, -vvv")
    parser.add_argument("-d", "--domain", action="store", required=True, help="Get results for a single domain.")
    #parser.add_argument("-iL", "--input-list", action="store", help="Input list of domains to check.")
    parser.add_argument("-p", "--proxy", action="store", help="Proxy to use, such as a rotating proxy. "
                                                              "Example: socks5://127.0.0.1:9050")
    parser.add_argument("-oC", "--csv-out", action="store", help="Dump results to csv file.")
    parser.add_argument("-oJ", "--json-out", action="store", help="Dump results to json file.")
    parser.add_argument("-x", action="store_true", help="Keeps selenium open (for debugging purposes).")

    args = parser.parse_args()

    if args.verbose:
        if args.verbose == 1:
            level = LVL.VERBOSE
        elif args.verbose == 2:
            level = LVL.DEBUG
        elif args.verbose == 3:
            level = LVL.SPAM
        else:
            level = LVL.NOTSET
    else:
        level = LVL.INFO
    # Init logging.
    setup(level=level)

    if which('geckodriver'):
        pass
    else:
        logger.error("Geckodriver not installed or not in $PATH: https://github.com/mozilla/geckodriver/releases")
        sys.exit(1)

    scrape = Scraper(
        proxy=args.proxy,
        csv_out=args.csv_out,
        json_out=args.json_out,
        x=args.x
    )

    if args.domain:
        all_results = scrape.domain_search(args.domain)
        if all_results:
            if args.csv_out:
                scrape.dump_csv([all_results])
            if args.json_out:
                scrape.dump_json([all_results])
    else:
        logger.info("Must supply either the -d or -iL options.")


if __name__ == "__main__":

    main()
