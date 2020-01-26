#
# Copyright (c) 2017-2018  Lionel Hercot <lhercot@cisco.com>
# All rights reserved.
#
import requests
import sys
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from flask import Flask
from flask import abort
from flask_restful import Api
from flask_restful import Resource
from flask_restful import reqparse
from flask import send_file
from pathlib import Path
from io import StringIO
from io import BytesIO
from ipaddress import IPv6Address
import os
import traceback
import CLEUCreds
from cleu.config import Config as C


from PIL import Image, ImageDraw


app = Flask(__name__)
api = Api(app)
# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE")
    return response


cmxBaseUrl = C.CMX
cmxAuth = (CLEUCreds.CMX_USERNAME, CLEUCreds.CMX_PASSWORD)
PORT = 8002

imgDir = "maps/"
markerDir = "markers/"
markerFiles = os.listdir(markerDir)
markers = {}
for filename in markerFiles:
    name = filename.split(".")[0]
    markers[name] = Image.open(markerDir + filename).convert("RGBA")
    markers[name].thumbnail((100, 100), Image.ANTIALIAS)
    # markerW, markerH = marker.size

apiUri = {
    "mac": "/api/location/v1/clients?macAddress=",
    "ip": "/api/location/v2/clients?ipAddress=",
    "map": "/api/config/v1/maps/imagesource/",
    "ssid": "/api/location/v2/clients/?include=metadata&pageSize=1000&page=",
    "count": "/api/location/v2/clients/count",
    "floors": "/api/config/v1/maps",
    "tag": "/api/location/v1/tags/",
}


def serve_pil_image(pil_img):
    img_io = BytesIO()
    pil_img.save(img_io, "JPEG", quality=100)
    img_io.seek(0)
    return send_file(img_io, mimetype="image/jpeg")


def getMap(imageName):
    imgFile = Path(imgDir + imageName)
    if not imgFile.is_file():
        respImg = requests.get(cmxBaseUrl + apiUri["map"] + imageName, auth=cmxAuth, verify=False, stream=True)
        if respImg.status_code == 200:
            with open(str(imgFile), "wb") as f:
                for chunk in respImg:
                    f.write(chunk)


def getAllFloorMaps():
    response = requests.get(cmxBaseUrl + apiUri["floors"], auth=cmxAuth, verify=False)
    floorList = {}
    if response and response != "":
        try:
            dataDict = json.loads(response.text)
            if "campuses" in dataDict:
                for campus in dataDict["campuses"]:
                    if "buildingList" in campus:
                        for building in campus["buildingList"]:
                            for floor in building["floorList"]:
                                floorId = floor["aesUid"]
                                imageName = floor["image"]["imageName"]
                                floorList[floorId] = imageName
                                getMap(imageName)
        except:
            print("Unexpected error" + str(sys.exc_info()[0]), file=sys.stderr)
            raise

    return floorList


class CMX(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("ip", help="IP address of the endpoint")
        parser.add_argument("ipv6", help="IPv6 address of the endpoint")
        parser.add_argument("mac", help="MAC address of the endpoint")
        parser.add_argument("marker", help="Marker used to display the location of the endpoint", default="marker")
        parser.add_argument("size", help="Size of the image returned")
        parser.add_argument("tag", help="Asset tag MAC address")

        args = parser.parse_args()
        response = ""
        if args.get("ip"):
            clientIp = args.get("ip")
            response = requests.get(cmxBaseUrl + apiUri["ip"] + clientIp, auth=cmxAuth, verify=False)
        elif args.get("tag"):
            clientMac = args.get("tag")
            response = requests.get(cmxBaseUrl + apiUri["tag"] + clientMac, auth=cmxAuth, verify=False)
        elif args.get("mac"):
            clientMac = args.get("mac")
            response = requests.get(cmxBaseUrl + apiUri["mac"] + clientMac, auth=cmxAuth, verify=False)
        elif args.get("ipv6"):
            clientIp = IPv6Address(args.get("ipv6")).exploded
            response = requests.get(cmxBaseUrl + apiUri["ip"] + clientIp, auth=cmxAuth, verify=False)

        markerName = args.get("marker")
        marker = markers["marker"]
        if markerName in markers:
            marker = markers[markerName]

        markerW, markerH = marker.size

        if response and response != "":
            try:
                dataDict = json.loads(response.text)
                result = None
                if args.get("tag") and dataDict and "mapInfo" in dataDict:
                    result = dataDict
                elif len(dataDict) > 0 and "mapInfo" in dataDict[0]:
                    result = dataDict[0]

                if result is not None:
                    imageName = result["mapInfo"]["image"]["imageName"]
                    mapLength = result["mapInfo"]["floorDimension"]["length"]
                    mapWidth = result["mapInfo"]["floorDimension"]["width"]
                    imageLength = result["mapInfo"]["image"]["height"]
                    imageWidth = result["mapInfo"]["image"]["width"]
                    coordX = result["mapCoordinate"]["x"]
                    coordY = result["mapCoordinate"]["y"]
                    positionX = (imageWidth / mapWidth) * coordX
                    positionY = (imageLength / mapLength) * coordY
                    getMap(imageName)
                    im = Image.open(str(imgDir + imageName))
                    positionX = positionX - markerW / 2
                    positionY = positionY - markerH
                    offset = (int(positionX), int(positionY))
                    im.paste(marker, offset, marker)
                    if args.get("size"):
                        # print('SIZE', file=sys.stderr)
                        size = args.get("size")
                        im.thumbnail((int(size), int(size)), Image.ANTIALIAS)

                    return serve_pil_image(im)
                else:
                    abort(404, "Requested element not found")
            except Exception as inst:
                print("Unexpected error with request= {} | error : {}".format(response.text, inst), file=sys.stderr)
                return {"response": str(response.text), "error": str(inst)}

        return abort(404, "Missing parameter ip, ipv6 or mac. Other possible parameters are: marker (" + ", ".join(markers.keys()) + ")")


class CMX_SSID(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("ssid", help="SSID used by the clients")
        parser.add_argument("floor", help="Floor used by the clients")
        parser.add_argument("marker", help="Marker used to display the location of the endpoint", default="marker")

        args = parser.parse_args()
        response = ""
        if args.get("ssid"):
            ssid = args.get("ssid")
            countResp = requests.get(cmxBaseUrl + apiUri["count"], auth=cmxAuth, verify=False)
            try:
                dataDict = json.loads(countResp.text)
                if "count" in dataDict:
                    count = dataDict["count"]
                    maxPageId = (count // 1000) + 1
                    print("Count: {} MaxPage: {}".format(count, maxPageId), file=sys.stderr)
                    userList = {}
                    floorList = getAllFloorMaps()
                    for pageId in range(1, maxPageId):
                        print("Page: {} MaxPage: {}".format(pageId, maxPageId), file=sys.stderr)
                        response = requests.get(cmxBaseUrl + apiUri["ssid"] + str(pageId), auth=cmxAuth, verify=False)
                        if response and response.text != "":
                            try:
                                userDict = json.loads(response.text)
                                for user in userDict:
                                    if user["ssId"] == ssid:
                                        floorName = user["mapInfo"]["floorRefId"]
                                        if floorName in userList:
                                            userList[floorName].append(user)
                                        else:
                                            userList[floorName] = [user]
                            except:
                                print(
                                    "Unexpected error with page request= " + response.text + " | error : " + str(sys.exc_info()[0]),
                                    file=sys.stderr,
                                )
                                return {"response": str(response.text), "error": str(inst)}

                    if args.get("floor"):
                        floor = args.get("floor")
                        if floor in userList:
                            markerName = args.get("marker")
                            marker = ""
                            if markerName in markers:
                                marker = markers[markerName]
                            else:
                                marker = markers["marker"]

                            markerW, markerH = marker.size
                            imageName = floorList[floorName]
                            getMap()
                            im = Image.open(str(imgDir + imageName))
                            for data in userList[floor]:
                                mapInfo = data["mapInfo"]
                                mapLength = mapInfo["floorDimension"]["length"]
                                mapWidth = mapInfo["floorDimension"]["width"]
                                imageLength = mapInfo["image"]["height"]
                                imageWidth = mapInfo["image"]["width"]
                                coordX = data["mapCoordinate"]["x"]
                                coordY = data["mapCoordinate"]["y"]
                                positionX = (imageWidth / mapWidth) * coordX
                                positionY = (imageLength / mapLength) * coordY

                                positionX = positionX - markerW / 2
                                positionY = positionY - markerH
                                offset = (int(positionX), int(positionY))
                                im.paste(marker, offset, marker)

                            return serve_pil_image(im)
                        elif floor in floorList:
                            imageName = floorList[floor]
                            getMap(imageName)
                            im = Image.open(str(imgDir + imageName))
                            return serve_pil_image(im)
                        else:
                            abort(404)
                    else:
                        return list(floorList.keys())
            except Exception as inst:
                print("Unexpected error with request= {} | error : {}".format(countResp, inst), file=sys.stderr)
                return {"response": str(countResp), "error": str(inst)}, 500


class sync(Resource):
    def get(self):
        return getAllFloorMaps()


class home(Resource):
    def get(self):
        return {}


api.add_resource(home, "/")
api.add_resource(CMX, "/api/v0.1/cmx")
api.add_resource(CMX_SSID, "/api/v0.1/ssid")
api.add_resource(sync, "/api/v0.1/sync")

if __name__ == "__main__":
    app.run(host=C.WSGI_SERVER, debug=True, port=PORT, threaded=True)
