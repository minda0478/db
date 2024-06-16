import re
import os
import json
from datetime import date
from cwe import cwe
from tqdm import tqdm

CVELIST_V5_DIR = '../cvelistV5-main/cvelistV5-main/cves/'
MAX_YEAR = 2025
MIN_YEAR = 1999

def copy_key_value(dic, copied, key):
    if key in copied:
        dic[key] = copied[key]

class cve_metadata:
    """
    cve metadata

    example
    id: CVE-2023-0001
    state: PUBLISHED
    date: 2022-10-27
    """

    def __init__(self, metadata):
        id_p = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
        uuid_p = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$")

        if not id_p.match(metadata["cveId"]) \
            or not uuid_p.match(metadata["assignerOrgId"]) \
            or (metadata["state"] != "PUBLISHED" \
            and metadata["state"] != "REJECTED"):
            raise Exception("no available cve metadata format")
        
        self.id = metadata["cveId"]
        self.state = metadata["state"]
        if "dataReserved" in metadata:
            self.date = date.fromisoformat(metadata["dataReserved"][:10])
        else:
            self.date = None
    def get_id(self):
        return self.id
    
    def is_published(self):
        return self.state == "PUBLISHED"
    
    def get_date(self):
        return self.date




class cve_container:
    def __init__(self, container):

        if "cna" not in container:
            raise Exception("no available cve container format")
        

        cna = container["cna"]

        uuid_p = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$")

        if "providerMetadata" not in cna \
            or not uuid_p.match(cna["providerMetadata"]["orgId"]):
            raise Exception("no provider metadata or no UUID format")
        
        self._set_dic_value(cna,"title")
        if "descriptions" not in cna:
            print(cna)
            raise Exception("no descriptions")

        self._set_descriptions(cna["descriptions"])

        if "affected" not in cna:
            raise Exception("no affected")
        
        self._set_affected(cna["affected"])

        self.cwes = []

        if "problemTypes" in cna:
            for prob_des in cna["problemTypes"]:
                for prob in prob_des["descriptions"]:
                    cwe_l = {}
                    cwe_p = re.compile(r"^CWE-[1-9][0-9]*$")
                    if "cweId" in prob:
                        cwe_l["id"] = cwe.get_cwe(prob["cweId"])
                    elif cwe_p.match(prob["description"]):
                        
                        cwe_l["id"] = cwe.get_cwe(next(cwe_p.finditer(prob["description"]))[0])
                    else:
                        continue

                    cwe_l["description"] = prob["description"]
                    self.cwes.append(cwe_l)
        
        if "references" not in cna:
            raise Exception("no references")

        self._set_dic_value(cna,"references")
        

        #workaround and solutions
        # ...

    def get_cwes(self):
        return self.cwes

    def get_affect(self):
        return self.affects

    def get_references(self):
        return self.references

    # private
    def _set_descriptions(self,descriptions):
        values = []

        lang_p = re.compile(r"^[A-Za-z]{2,4}([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$")
        en_p = re.compile(r"^en([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$")
        for des in descriptions:
            if "lang" not in des \
                or not lang_p.match(des["lang"]) \
                or "value" not in des:
                raise Exception("not available description format")
            
            if en_p.match(des["lang"]):
                values.append(des["value"])

        if not values:
            raise Exception("not available description format")

        self.descriptions = values
            
    def _set_affected(self,affected):
        if len(affected) == 0:
            raise "no affected"
        
        self.affects = []

        for affect in affected:
            affect_info = {}
            if not (("vendor" in affect and "product" in affect) \
                or ("packageName" in affect and "collectionURL" in affect)):
                raise Exception("not available affect format")
            
            if "versions" not in affect and "defaultStatus" not in affect:
                raise Exception("not available affect format")

            # if not exist version then skip?

            copy_key_value(affect_info,affect,"vendor")
            copy_key_value(affect_info,affect,"product")
            copy_key_value(affect_info,affect,"collectionURL")
            copy_key_value(affect_info,affect,"packageName")
            copy_key_value(affect_info,affect,"modules")
            copy_key_value(affect_info,affect,"programFiles")
            copy_key_value(affect_info,affect,"platforms")
            copy_key_value(affect_info,affect,"repo")
            if "programRoutines" in affect:
                affect_info["programRoutines"] = list(map(lambda x: x["name"], affect["programRoutines"]))

            if "versions" in affect:
                for ver in affect["versions"]:
                    if ver["status"] == "affected":
                        affect_info["version"] = ver["version"]
                        copy_key_value(affect_info,ver,"lessThan")

            self.affects.append(affect_info)

    def _set_dic_value(self,dic,key,name=None):
        if name == None:
            name = key
        if key in dic:
            setattr(self, name, dic[key])

    def get_description(self):
        return self.descriptions[0]
            
    def get_descriptions(self):
        return self.descriptions
#
# https://cveproject.github.io/cve-schema/schema/docs/
#
class cve:
    def __init__(self, cve_json):
        version_p = re.compile(r"^5\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$")

        if cve_json["dataType"] != "CVE_RECORD" \
            or not version_p.match(cve_json["dataVersion"]) \
            or "cveMetadata" not in cve_json \
            or "containers" not in cve_json:
            raise Exception("no available cve format")
        
        self.metadata = cve_metadata(cve_json["cveMetadata"])
        if not self.is_published():
            self.container = None
            return
        
        self.container = cve_container(cve_json["containers"])

    def get_id(self):
        return self.metadata.get_id()
    
    def is_published(self):
        return self.metadata.is_published()

    def get_affect(self):
        return self.container.get_affect()
    
    def get_cwes(self):
        ret = set()
        for c in self.container.get_cwes():
            ret.add(c["id"])
        
        return ret
    
    def get_desc(self):
        return self.container.get_description()
    
    def get_descs(self):
        return self.container.get_descriptions()

    def get_ref(self):
        return self.container.get_references()

    def for_analyze(self):
        affs = self.get_affect()
        vendor = None
        product = None
        package_name = None

        for aff in affs:
            if "vendor" in aff:
                vendor = aff["vendor"]
            if "product" in aff:
                product = aff["product"]
            if "package_name" in aff:
                package_name = aff["package_name"]
            
            if vendor and product:
                break

        return (vendor,product,package_name)

def extend_cve_json(cve_dir, base_path, cve_list):
    result = cve_dir

    for cve_path in tqdm(cve_list,desc=base_path):
        path = base_path + '/' + cve_path

        key = cve_path[:-5]
        with open(path,'r',encoding='utf-8') as cve_json:
            value = cve(json.load(cve_json))

        result[key] = value 
    return result

def all_dir_scan(min_year=1999,max_year=2025,jump=1):
    if MAX_YEAR < max_year or MIN_YEAR > min_year or max_year < min_year:
        raise Exception("out of bound year\n\nmin year: %d\nmax year: %d"%(min_year,max_year))
    
    result = {}

    for year in tqdm(range(min_year,max_year,jump),desc=f'{min_year}~{max_year-1}'):
        year_dir = {}
        year_path = CVELIST_V5_DIR + str(year)
        for path in tqdm(os.listdir(year_path),desc=year_dir):
            cve_list = os.listdir(year_path+ '/' + path)
            year_dir = extend_cve_json(year_dir, year_path+'/'+path, cve_list)
        


        result[str(year)] = year_dir

    return result



if __name__ == "__main__":
    print(cwe.get_cwe("CWE-416").metadata.name)