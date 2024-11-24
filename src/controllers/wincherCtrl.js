const { get } = require("lodash");
const dvAxios = require("devergroup-request").default;
const axios = new dvAxios({
  axiosOpt: {
    timeOut: 30000,
  },
});
const { wincherLog } = require("../services/logger");
const SettingModel = require("../models/setting");
const CredentialModel = require("../models/credential");

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const body = `grant_type=password&client_id=wincher-web&scope=api offline_access&username=${email}&password=${password}`;
    const response = await axios.instance.post(
      "https://auth.wincher.com/connect/token",
      body,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(body),
          Origin: "https://app.wincher.com",
          Referer: "https://app.wincher.com/",
        },
      }
    );
    if (response.status == 200) {
      let cookie = `wincher_access_token=${response.data.access_token}; wincher_httpreferer=https://accounts.google.com/; wincher_refresh_token=${response.data.refresh_token};`;
      await CredentialModel.findOneAndUpdate(
        {
          type: "wincher",
        },
        {
          username: email,
          password: password,
        },
        {
          upsert: true,
        }
      );
      await SettingModel.findOneAndUpdate(
        null,
        {
          wincherCookie: cookie,
        },
        {
          upsert: true,
        }
      );
      wincherLog.info(`Start session with ${email} successfully.`)
      return res.send("Login successfully.");
    } else {
      wincherLog.error(`Start session with ${email} failed.`);
      return res
        .status(500)
        .send(get(err, "response.data.message") || err.toString());
    }
  } catch (err) {
    wincherLog.error(`Start session with ${email} failed: ${get(err, 'response')}`);
    return res.status(500).send(err.message);
  }
};

module.exports = { login };
