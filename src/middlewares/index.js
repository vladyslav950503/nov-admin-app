const crypto = require("node:crypto");
const { serverLog } = require("../services/logger");
const base64 = require("nodejs-base64-encode");
const Settings = require("../models/setting");
const Site = require("../models/site");
const sessionMapper = new Map();

const notFoundMiddleware = (req, res, next) => {
  res.status(404);
  const error = new Error(`🔍 - Not Found - ${req.originalUrl}`);
  next(error);
};

const errorHandleMiddleware = (err, req, res, next) => {
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === "production" ? "🥞" : err.stack,
  });
};

const isAccessable = async (uid, site) => {
  let setting = await Settings.findOne();
  let check = false;
  if (setting) {
      for(let i = 0; i < setting.membershipLids.length; i++) {
          let lid = setting.membershipLids[i];
          let result = await getMembership(uid, lid, site);
          if (result != 0) {
              check = true;
              break;
          }
      }
  }
  return check;
}

const getMembership = async (uid, lid, siteUrl) => {
  try {
    let site = await Site.findOne({ url: siteUrl });
    serverLog.error(`Missing config for ${siteUrl}`);
    let { data } = await axios.get(
      `${siteUrl}/wp-content/plugins/indeed-membership-pro/apigate.php?ihch=${site.membershipApiKey}&action=verify_user_level&uid=${uid}&lid=${lid}`
    );
    return data.response;
  } catch (err) {
    return false;
  }
};

const getMainDomain = (domain) => {
  let segments = domain.split(".");
  let mainDomain = "";
  for (let i = 0; i < segments.length; i++) {
    if (i > 0) mainDomain += "." + segments[i];
  }
  return mainDomain;
};

const authMiddleware = async (req, res, next) => {
  const domain = req.headers["host"];
  const userAgent = req.headers["user-agent"];
  const ipAddr = req.socket.remoteAddress;
  const { token, site } = req.body;
  if (typeof token !== "string" || !/.+#.+#.+/.test(token)) {
    return res.render("error", {
      msg: `Corrputed token [${token}] sent from IP: ${ipAddr}`,
    });
  }

  const tokenParts = token.split("#");
  if (tokenParts.length !== 3) {
    return res.render("error", {
      msg: `Corrupted token [${token}] sent from IP: ${ipAddr}`,
    });
  }
  const sentSignature = base64.decode(tokenParts[0], "base64");
  const time = base64.decode(tokenParts[1], "base64");
  const data = base64.decode(tokenParts[2], "base64");
  const parsedUserData = JSON.parse(data);
  const rawString = `${userAgent}\n${time}${data}`;
  const userId = parsedUserData[0];
  const userCookie = parsedUserData[1];
  const userType = parsedUserData[3];
  const serverSignature = crypto
    .createHmac("sha1", process.env.PRIVATE_KEY)
    .update(Buffer.from(rawString, "utf-8"))
    .digest("hex");

  if (sentSignature !== serverSignature) {
    return res.render("error", {
      msg: `Received signature: ${sentSignature} is different from ${serverSignature}`,
    });
  } else if (!Array.isArray(parsedUserData)) {
    return res.render("error", {
      msg: `Invalid user data: ${JSON.stringify(parsedUserData)}`,
    });
  } else if (parsedUserData.length !== 4) {
    return res.render("error", {
      msg: `Invalid user data (array size should be 5): ${JSON.stringify(
        parsedUserData
      )}`,
    });
  } else {
    const user = {
      id: userId,
      isAdmin: userType,
      username: userCookie.split("=")[1].split("|")[0],
      accessAble: userType ? true : await isAccessable(userId, site),
    };

    res.cookie("wpToken", token, {
      path: "/",
      domain:
        process.env.NODE_ENV === "development"
          ? undefined
          : getMainDomain(domain),
    });
    res.cookie("wpInfo", base64.encode(JSON.stringify({ user, site })), {
      path: "/",
      domain:
        process.env.NODE_ENV === "development"
          ? undefined
          : getMainDomain(domain),
    });
  }
  next();
};

const adminMiddleware = (req, res, next) => {
  const { wpInfo, wpToken } = req.cookies;
  if (!wpInfo || !wpToken)
    return res.render("error", {
      msg: "Access denined.",
    });
  const userAgent = req.headers["user-agent"];
  const ipAddr = req.socket.remoteAddress;
  if (typeof wpToken !== "string" || !/.+#.+#.+/.test(wpToken)) {
    return res.render("error", {
      msg: `Corrputed token [${wpToken}] sent from IP: ${ipAddr}`,
    });
  }

  const tokenParts = wpToken.split("#");
  if (tokenParts.length !== 3) {
    return res.render("error", {
      msg: `Corrupted token [${wpToken}] sent from IP: ${ipAddr}`,
    });
  }

  const sentSignature = base64.decode(tokenParts[0], "base64");
  const time = base64.decode(tokenParts[1], "base64");
  const data = base64.decode(tokenParts[2], "base64");
  const rawString = `${userAgent}\n${time}${data}`;
  const serverSignature = crypto
    .createHmac("sha1", process.env.PRIVATE_KEY)
    .update(Buffer.from(rawString, "utf-8"))
    .digest("hex");

  if (sentSignature !== serverSignature) {
    return res.render("error", {
      msg: `Received signature: ${sentSignature} is different from ${serverSignature}`,
    });
  }
  const wpInfoDecoded = JSON.parse(base64.decode(wpInfo));
  if (!wpInfoDecoded.user.isAdmin)
    return res.render("error", {
      msg: "Restricted Access.",
    });
  next();
};

module.exports = {
  notFoundMiddleware,
  errorHandleMiddleware,
  authMiddleware,
  adminMiddleware,
};
