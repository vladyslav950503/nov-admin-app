const { get } = require("lodash");
const dvAxios = require("devergroup-request").default;
const axios = new dvAxios({
  axiosOpt: {
    timeout: 30000,
  },
});
const settingModel = require("../models/setting");
const credentialModel = require("../models/credential");
const { searchatlasLog } = require("../services/logger");

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data } = await axios.instance.post(
      "https://api.searchatlas.com/api/token/",
      {
        username: email,
        password: password,
      },
      {
        headers: {
          Origin: "https://dashboard.searchatlas.com",
          Referrer: "https://dashboard.searchatlas.com/",
        },
      }
    );
    if (data && data.token) {
      await credentialModel.findOneAndUpdate(
        { type: "searchatlas" },
        {
          type: "searchatlas",
          username: email,
          password: password,
        },
        {
          upsert: true,
        }
      );
      await settingModel.findOneAndUpdate(
        null,
        {
          searchatlasCookie: data.token,
        },
        {
          upsert: true,
        }
      );
      res.send("Login successfully.");
    } else {
      res.status(500).send("Credential is incorrect.");
    }
  } catch (err) {
    searchatlasLog.error(
      `Start session with ${email} failed: ${
        get(err, "response.data.message") || err.toString()
      }`
    );
    res.status(500).send(get(err, "response.data.message") || err.toString());
  }
};

module.exports = {
  login,
};
