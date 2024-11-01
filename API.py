import Utils


def get_prediction(url, model):
    output = {
        "SCORE": 180,
        "InTop1Million": False,
        "InURLVoidBlackList": False,
        "isHTTPS": True,
        "hasSSLCertificate": True,
        "GoogleSafePassed": True,
        "InMcaffeBlackList": False,
        "InSucuriBlacklist": False,
        "isTemporaryDomain": False,
        "isOlderThan3Months": True,
        "isBlackListedinIpSets": False,
        "target_urls": None,
        "Model Prediction": "Safe"
    }

    try:
        print("Finding Target URLs...")
        target_urls = Utils.find_target_urls(url, 8)
        output["target_urls"] = target_urls
    except:
        print("Error Occured while finding target Urls !")

    if Utils.check_top1million_database(url):
        output["InTop1Million"] = True

    if Utils.check_top1million_database_2(url):
        output["InTop1Million"] = True

    if output["InTop1Million"] == True:
        return output

    if Utils.checkURLVoid(url) > 0:
        output["SCORE"] = output["SCORE"] - 20
        output["InURLVoidBlackList"] = True
        print("URL is blacklisted in UrlVoid's system !")
    else:
        print("URL is Safe in UrlVoid's system !")

    if Utils.check_ssl_certificate(url) != True:
        output["hasSSLCertificate"] = False
        print("URL has not SSL Certificate !")
        output["SCORE"] = output["SCORE"] - 20

    if output["hasSSLCertificate"] != True and Utils.is_https(url) != True:
        print("URL is not HTTP secure")
        output["isHTTPS"] = False

    if Utils.check_google_safe_browsing(url) != True:
        output["GoogleSafePassed"] = False
        output["SCORE"] = output["SCORE"] - 20

    if Utils.check_Nortan_WebSafe(url) != True:
        output["SCORE"] = output["SCORE"] - 20

    if Utils.check_mcafee_database(url) != True:
        output["InMcaffeBlackList"] = True
        output["SCORE"] = output["SCORE"] - 10

    if Utils.checkSucuriBlacklists(url) != True:
        output["InSucuriBlacklist"] = True
        output["SCORE"] = output["SCORE"] - 10

    if Utils.is_temporary_domain(url):
        print("Domain is registered from unsecure source")
        output["isTemporaryDomain"] = True
        output["SCORE"] = output["SCORE"] - 10

    if Utils.get_days_since_creation(url, 3) != True:
        print("Domain is less than 3 months old")
        output["isOlderThan3Months"] = False
        output["SCORE"] = output["SCORE"] - 10

    if Utils.checkLocalBlacklist(url):
        print("The URL is blacklisted !")
        output["SCORE"] = output["SCORE"] - 20

    if Utils.is_valid_ip(url) == True:
        if Utils.check_ip_in_ipsets(url):
            print("The IP address is blacklisted !")
            output["isBlackListedinIpSets"] = True
            output["SCORE"] = output["SCORE"] - 20
    else:
        print("Given address is not an valid IP address !")

    if Utils.isURLMalicious(url, model) == 1:
        print("Model predicted the URL as malicious")
        output["Model Prediction"] = "Malicious"
        output["SCORE"] = output["SCORE"] - 20
    else:
        print("Model predicted URL not malicious !")

    if Utils.url_in_reporting_database(url):
        print("URL is also present in the Reporting database !")
        output["SCORE"] = output["SCORE"] - 20
    else:
        print("URL not in Reporting Database !")

    return output
