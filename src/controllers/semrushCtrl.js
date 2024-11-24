const crypto = require("node:crypto");
const settingModel = require("../models/setting");
const { semrushLog } = require("../services/logger");
const { get } = require("lodash");
const dvAxios = require("devergroup-request").default;
const captcha = require("2captcha");
const axios = new dvAxios({
    axiosOpt: {
        timeout: 30000
    }
});

const login = async (req, res) => {
    let { email, password } = req.body;
    try {              
        let siteKey = "6Ldw6DYUAAAAACFCNmvsT32P6VPVonpjbSS7XTA9";
        let solver = new captcha.Solver(process.env.TWO_CAPTCHA_KEY);
        let response = await solver.recaptcha(siteKey, "https://www.semrush.com/login");
        let body = JSON.stringify({
            email,
            password,
            locale: "en",
            source: "semrush",
            "g-recaptcha-response": response.data,
            "user-agent-hash": crypto.createHash("sha1").update(email).digest("hex").substring(0, 32)
        });
        let { data } = await axios.instance.post(
            "https://www.semrush.com/sso/authorize",
            body, 
            {
                headers: {
                    "Origin": "https://www.semrush.com",
                    "Referer": "https://www.semrush.com/login?src=header",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json; charset=UTF-8",
                    "Content-Length": Buffer.from(body, 'utf-8')
                }
            }
        );
        if (data.user_id) {
            let cookie = axios.cookieJar.getCookieStringSync("https://www.semrush.com");
            await settingModel.findOneAndUpdate(null, { 
                semrushCookie: cookie
            }, {
                upsert: true
            });
            semrushLog.info(`Start session with ${email} successfully.`);
            res.send("Login successfully.");
        } else {
            res.status(500).send("Credential is incorrect.");
        }
    } catch (err) {
        semrushLog.error(`Start session with ${email} failed: ${get(err, "response.data.message") || err.toString()}`);
        res.status(500).send(get(err, "response.data.message") || err.toString());
    }
}

module.exports = {
    login
};