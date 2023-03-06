import pandas as pd
import requests
import csv
from flask import Flask,render_template
import base64
import requests
import json
import os
import hashlib
from io import StringIO

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
app = Flask(__name__)
app.config.from_object('config')
urlAuth = "https://auth.anaplan.com/token/authenticate"
urlStem = "https://api.anaplan.com/2/0"

@app.route('/')
class anaplanImport(object):
  @classmethod
  def executeImport(cls, email, password, modelName, importName, content):
    # Get the token
    tokenValue = cls.getTokenBasicAuth(email, password)
    # tokenValue = cls.getTokenCACErt(caCert, privateKey)
    # Get the list of models and choose one
    print(tokenValue)
    modelInfos = cls.getWsModelIds(tokenValue, modelName)
    print(modelInfos)
    modelId = modelInfos[0]
    workspaceId = modelInfos[1]
    importInfos = cls.getImportInfo(tokenValue, workspaceId, modelId, importName)
    print(importInfos)
    importId = importInfos[0]
    datasourceId = importInfos[1]
    status_code = cls.sendData(tokenValue, workspaceId, modelId, datasourceId, 1, content)
    print(status_code)
    taskId = cls.importTrigger(tokenValue, workspaceId, modelId, importId)
    print(taskId)
    checkStatus = cls.checkImportStatus(tokenValue, workspaceId, modelId, importId, taskId)
    print(checkStatus)

  @classmethod
  def getTokenBasicAuth(cls, email, password):
    # Get the token
    cred64 = convertbase64(email + ":" + password)
    headers = {'Authorization': 'Basic %s' % cred64}
    rawResponse = requests.post(
      urlAuth,
      headers=headers
    )
    jsonResponse = json.loads(rawResponse.content)
    tokenValue = jsonResponse["tokenInfo"]["tokenValue"]
    return tokenValue

  @classmethod
  def getTokenCACErt(cls, caCert, pKey):
    with open(caCert, "r") as my_pem_file:
      my_pem_text = my_pem_file.read()
    json_body = openssl_private_encrypt(pKey)
    header_string = {
      'AUTHORIZATION': 'CACertificate ' + base64.b64encode(my_pem_text.encode('utf-8')).decode('utf-8')}
    anaplan_url = 'https://auth.anaplan.com/token/authenticate'
    r = requests.post(anaplan_url, headers=header_string, data=json.dumps(json_body))
    rJson = json.loads(r.content)
    tokenValue = rJson["tokenInfo"]["tokenValue"]
    return tokenValue

  @classmethod
  def getWsModelIds(cls, token, modelName):
    # Get the list of models and choose one with the model id and the workspaceId
    headers = {'Authorization': 'AnaplanAuthToken %s' % token}
    response = requests.get(
      urlStem + "/models",
      headers=headers
    )
    jsonResponse = json.loads(response.content)
    modelsArray = jsonResponse["models"]
    modelInfo = [model for model in modelsArray if model['name'] == modelName]
    modelId = modelInfo[0]["id"]
    wsId = modelInfo[0]["currentWorkspaceId"]
    return modelId, wsId

  @classmethod
  def getImportInfo(cls, token, wsId, modelId, importName):
    # Get the list of imports and choose one with the importId and the datasourceId
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    response = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/imports",
      headers=headers
    )
    jsonResponse = json.loads(response.content)
    importsArray = jsonResponse["imports"]
    importsInfo = [importInfo for importInfo in importsArray if importInfo['name'] == importName]
    importId = importsInfo[0]["id"]
    datasourceId = importsInfo[0]["importDataSourceId"]
    return importId, datasourceId

  @classmethod
  def sendData(cls, token, wsId, modelId, fileId, chunkCount, content):
    # Send the data to Anaplan to update datasource
    ## First, tell Anaplan API's server it will receive one chunk
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    data = json.dumps({'id': fileId, "chunkCount": chunkCount})
    response = requests.post(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/files/" + fileId,
      headers=headers,
      data=data
    )
    ## Now let's send the file
    headers2 = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/octet-stream'}
    response2 = requests.put(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/files/" + fileId + "/chunks/" + str(
        chunkCount - 1)
      ,
      headers=headers2,
      data=content
    )
    status_code = response2.status_code
    return status_code

  @classmethod
  def importTrigger(cls, token, wsId, modelId, importId):
    # Finally we trigger the import
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    data = json.dumps({'localeName': "en_US"})
    response = requests.post(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/imports/" + importId + "/tasks/",
      headers=headers,
      data=data
    )
    # Get the taskId
    jsonResponse = json.loads(response.content)
    taskId = jsonResponse["task"]["taskId"]
    return taskId

  @classmethod
  def checkImportStatus(cls, token, wsId, modelId, importId, taskId):
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    response = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/imports/" + importId + "/tasks/" + taskId,
      headers=headers
    )
    response_content = response.content
    return response_content

  #######################################################################################      export  #######################################################################
  @classmethod
  def executeExport(cls, email, password, modelName, exportName):
    # Get the token
    tokenValue = cls.getTokenBasicAuth(email, password)
    # tokenValue = cls.getTokenCACErt(caCert, privateKey)
    # Get the list of models and choose one
    print(tokenValue)
    modelInfos = cls.getWsModelIds(tokenValue, modelName)
    print(modelInfos)
    modelId = modelInfos[0]
    workspaceId = modelInfos[1]
    exportInfos = cls.getExportInfo(tokenValue, workspaceId, modelId, exportName)
    print(exportInfos)
    exportId = exportInfos[0]
    datasourceId = exportInfos[1]
    taskId = cls.exportTrigger(tokenValue, workspaceId, modelId, exportId)
    print(taskId)
    checkStatus, data = cls.saveData(tokenValue, workspaceId, modelId, exportId)
    print(checkStatus)
    string = data.decode('utf-8')
    df = pd.read_csv(StringIO(string))
    print(df)

  @classmethod
  def getExportInfo(cls, token, wsId, modelId, exportName):
    # Get the list of exports and choose one with the exportId and the exportType
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    response = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/exports",
      headers=headers
    )
    jsonResponse = json.loads(response.content)
    exportsArray = jsonResponse["exports"]
    exportsInfo = [exportInfo for exportInfo in exportsArray if exportInfo['name'] == exportName]
    exportId = exportsInfo[0]["id"]
    exportType = exportsInfo[0]["exportType"]
    return exportId, exportType

  @classmethod
  def exportTrigger(cls, token, wsId, modelId, exportId):
    # Finally we trigger the import
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    data = json.dumps({'localeName': "en_US"})
    response = requests.post(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/exports/" + exportId + "/tasks/",
      headers=headers,
      data=data
    )
    # Get the taskId
    jsonResponse = json.loads(response.content)
    taskId = jsonResponse["task"]["taskId"]
    return taskId

  @classmethod
  def checkExportStatus(cls, token, wsId, modelId, exportId, taskId):
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    response = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/exports/" + exportId + "/tasks/" + taskId,
      headers=headers
    )
    response_content = response.content
    return response_content

  @classmethod
  def saveData(cls, token, wsId, modelId, fileId):
    # save the data to Anaplan to update datasource
    headers1 = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    response = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/files",
      headers=headers1
    )
    jsonResponse = json.loads(response.content)
    print(jsonResponse)
    exportsArray = jsonResponse["files"]
    exportsInfo = [exportInfo for exportInfo in exportsArray if exportInfo['id'] == fileId]
    chunkCount = exportsInfo[0]["chunkCount"]
    print("chunkCount :", chunkCount)
    ## First, tell Anaplan API's server it will receive one chunk
    headers = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/json'}
    response = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/files/" + fileId + "/chunks",
      headers=headers,
    )
    jsonResponse = json.loads(response.content)
    print(jsonResponse)
    exportsArray = jsonResponse["chunks"]
    exportsInfo = [exportInfo for exportInfo in exportsArray if exportInfo['name'] == "chunk" + str(chunkCount - 1)]
    print(exportsArray)
    chunkID = exportsArray[0]["id"]
    print(chunkID)
    ## Now let's save the file
    headers2 = {'Authorization': 'AnaplanAuthToken %s' % token, 'Content-Type': 'application/octet-stream'}
    response2 = requests.get(
      urlStem + "/workspaces/" + wsId + "/models/" + modelId + "/files/" + fileId + "/chunks/" + chunkID
      ,
      headers=headers2)
    status_code = response2.status_code
    return status_code, response2.content


#######################################################################################    Fin export  #####################################################################

def sign_string(privkeyfile, message):
  with open(privkeyfile) as f:
    privkey = serialization.load_pem_private_key(
      f.read().encode('utf-8'), password=None, backend=default_backend())

  prehashed = hashlib.sha512(message).hexdigest()

  sig = privkey.sign(
    prehashed.encode('utf-8'),
    padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512())

  return base64.b64encode(sig).decode('utf-8')


def openssl_private_encrypt(privateKey):
  """Encrypt data with RSA private key.
  This is a rewrite of the function from PHP, using cryptography
  FFI bindings to the OpenSSL library. Private key encryption is
  non-standard operation and Python packages either don't offer
  it at all, or it's incompatible with the PHP version.
  The backend argument MUST be the OpenSSL cryptography backend.
  """
  # usage
  data = os.urandom(150)
  key = load_pem_private_key(open(privateKey).read().encode('utf-8'), None, backend=default_backend())
  backend = default_backend()
  signature = key.sign(
    data,
    padding.PKCS1v15(
    )
    ,
    hashes.SHA512()
  )
  # print(signature)
  signed_nonce = base64.b64encode(signature).decode('utf-8')  # base64.b64encode(data).decode('utf-8'))
  json_string = '{ "encodedData":"' + str(
    base64.b64encode(data).decode('utf-8')) + '", "encodedSignedData":"' + signed_nonce + '"}'
  # print(json_string)
  return json_string


def importCsv(url):
  response = requests.get(url).content
  return response


def convertbase64(connectString):
  cred64 = base64.b64encode(bytes(connectString, 'UTF-8')).decode('utf-8')
  return cred64


anaplanimp = anaplanImport()

###############################################################################################################################
"""
dt= pd.read_csv("Tarifs_parts.csv",sep=";", encoding = 'utf8')
cols=dt.columns
df = pd.read_csv("Tarifs_parts.csv", delimiter=";", decimal=",")
df_str = df.to_csv(sep=";", index=False)
df_str


Year=dt['DT_DER_VALO'].str[-2:]
Year=Year.astype('int')
dt=dt.drop(Year[Year<=20].index)
dt=dt.drop(Year[Year>=23].index)
dt.shape

Month= dt['DT_CLOTURE']
Month=pd.DataFrame(Month.astype('str'))
Month=Month['DT_CLOTURE'].str[-2:]
dt['ISIN x Date']=dt['CD_PART_ISIN']+"_"+Month+"_"+dt['DT_DER_VALO'].str[-2:]

"""
#################################################################################################################################


def main():
  try:
    # Get the data from the source
    # data_content = bytes(dt,encoding="utf-8")
    # print(data_content)
    anaplanImport = anaplanimp.executeExport("salah.el-habachi@asterigo.com", "Khatibhafida1999!", "[STG] Python",
                                             "Grid - ISIN x Date.csv")
    # anaplanImport = anaplanimp.executeImport("salah.el-habachi@asterigo.com", "Khatibhafida1999!","[STG] Python","IMP_MOD_STG01_TO_LIST_ISIN x Date [Python]",data_content)

  except:
    print("An exception occurred")


@app.route("/anap")
def index():
    return render_template('anap.html', output=main())

if __name__ == '__main__':
    app.run()



