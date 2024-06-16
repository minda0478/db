import csv
import re





class cwe_metadata:
    def __init__(self, cwe_dict):
        self.id = cwe_dict["CWE-ID"]
        self.name = cwe_dict["Name"]
        self.state = cwe_dict["Status"]

class cwe_container:
    def __init__(self, cwe_dict):
        self.abstract = cwe_dict["Weakness Abstraction"]
        self.description = cwe_dict["Description"]
        self._set_dic_value(cwe_dict,"Extended Description","extra_description")
        self._set_dic_value(cwe_dict,"Weakness Ordinalities","ordinalities")
        
        if cwe_dict["Related Weaknesses"] != "":
            self.related = self.parse_data(cwe_dict["Related Weaknesses"])

        if cwe_dict["Applicable Platforms"] != "":
            self.platforms = self.parse_data(cwe_dict["Applicable Platforms"])

        if cwe_dict["Alternate Terms"] != "":
            self.terms = self.parse_data(cwe_dict["Alternate Terms"])

        # Common Consequences

        if cwe_dict["Detection Methods"] != "":
            self.detect = self.parse_data(cwe_dict["Detection Methods"])
        
        # Potential Mitigations

        # Related Attack Patterns

        if cwe_dict["Notes"] != "":
            self.notes = self.parse_data(cwe_dict["Notes"])

    def _set_dic_value(self,dic,key,name=None):
        if name == None:
            name = key
        if dic[key] != "":
            setattr(self, name, dic[key])

    def parse_data(self, data):
        if ':' not in data:
            return data

        data = data.strip('::')
        result = []

        for elem in data.split('::'):
            dict_data = {}
            
            colon_count = elem.count(':')
            for _ in range(colon_count//2):
                key,elem = elem.split(':',1)
                value,elem = elem.split(':',1)
                dict_data[key] = value

            if ':' in elem:
                key,value = elem.split(':')
            else:
                key,value = elem,None

            dict_data[key] = value

            result.append(dict_data)
            
        return result
        
#https://cwe.mitre.org/documents/schema/index.html#AbstractionEnumeration
class cwe:
    cwes = {}
    
    def __init__(self, cwe_data):
        if type(cwe_data) == str:
            id = cwe_data
        elif type(cwe_data) == dict:
            id = "CWE-"+cwe_data["CWE-ID"]

        if not self._check_id(id):
            raise Exception("not available cwe format")

        if self.exist_id(id):
            return self.get_cwe(id)
        
        self.metadata = cwe_metadata(cwe_data)
        self.container = cwe_container(cwe_data)

        cwe.cwes[id] = self

    def get_metadata(self, id):
        return self.metadata


    @classmethod
    def get_cwe(cls, id):
        check = cls.exist_id(id)
        if check == True:
            return cls.cwes[id]
        elif check == False:
            return id
        else:
            return None
            

    @classmethod
    def exist_id(cls, id):
        if not cls._check_id(id):
            return None
        elif id in cls.cwes:
            return True
        else:
            return False
        
    @classmethod
    def _check_id(cls, id):
        cwe_p = re.compile(r"^CWE-[1-9][0-9]*$")
        if cwe_p.match(id):
            return True
        else:
            return False
        

def set_all_cwe(path="C:/assignment/wert/cwe_list/1000.csv"):
    cwe_file = open(path,'r',encoding='utf-8')

    cwe_rdr = csv.DictReader(cwe_file)
    
    for cwe_data in cwe_rdr:
        cwe(cwe_data)

    cwe_file.close()
    
set_all_cwe()

def test(key, m):
    pass

if __name__ == "__main__":
    print(cwe.get_cwe("CWE-416").metadata.name)