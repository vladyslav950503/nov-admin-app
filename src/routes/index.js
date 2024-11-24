const express = require("express");
const router = express.Router();

const { authMiddleware, adminMiddleware } = require("../middlewares");

const semrushCtrl = require("../controllers/semrushCtrl");
const spyfuCtrl = require("../controllers/spyfuCtrl");
const seolyzeCtrl = require("../controllers/seolyzeCtrl");
const sistrixCtrl = require("../controllers/sistrixCtrl");
const linkcentaurCtrl = require("../controllers/linkcentaurCtrl");
const spamzillaCtrl = require("../controllers/spamzillaCtrl");
const seodityCtrl = require("../controllers/seodityCtrl");
const rytrmeCtrl = require("../controllers/rytrmeCtrl");
const wordaiCtrl = require("../controllers/wordaiCtrl");
const keywordCtrl = require("../controllers/keywordCtrl");
const nichescraperCtrl = require("../controllers/nichescraperCtrl");
const pipiadsCtrl = require("../controllers/pipiadsCtrl");
const keywordkegCtrl = require("../controllers/keywordkegCtrl");
const paraphraserCtrl = require("../controllers/paraphraserCtrl");
const buzzsumoCtrl = require("../controllers/buzzsumoCtrl");
const articleforgeCtrl = require("../controllers/articleforgeCtrl");
const bigspyCtrl = require("../controllers/bigspyCtrl");
const colinkriCtrl = require("../controllers/colinkriCtrl");
const dinorankCtrl = require("../controllers/dinorankCtrl");
const yourtextCtrl = require("../controllers/yourtextCtrl");
const babbarCtrl = require("../controllers/babbarCtrl");
const firstfrCtrl = require("../controllers/firstfrCtrl");
const textoptimizerCtrl = require("../controllers/textoptimizerCtrl");
const onehourindexingCtrl = require("../controllers/onehourindexingCtrl");
const ranxplorerCtrl = require("../controllers/ranxplorerCtrl");
const woorankCtrl = require("../controllers/woorankCtrl");
const seobserverCtrl = require("../controllers/seobserverCtrl");
const seozoomCtrl = require("../controllers/seozoomCtrl");
const affilistingCtrl = require("../controllers/affilistingCtrl");
const explodingtopicsCtrl = require("../controllers/explodingtopicsCtrl");
const localrankerCtrl = require("../controllers/localrankerCtrl");
const prowritingaidCtrl = require("../controllers/prowritingaidCtrl");
const copyscapeCtrl = require("../controllers/copyscapeCtrl");
const keywordcupidCtrl = require("../controllers/keywordcupidCtrl");
const serpstatCtrl = require("../controllers/serpstatCtrl");
const plagiumCtrl = require("../controllers/plagiumCtrl");
const closerscopyCtrl = require("../controllers/closerscopyCtrl");
const linkodyCtrl = require("../controllers/linkodyCtrl");
const alisharkCtrl = require("../controllers/alisharkCtrl");
const pexdaCtrl = require("../controllers/pexdaCtrl");
const zonbaseCtrl = require("../controllers/zonbaseCtrl");
const dropshipCtrl = require("../controllers/dropshipCtrl");
const espinnerCtrl = require("../controllers/espinnerCtrl");
const asinseedCtrl = require("../controllers/asinseedCtrl");
const sellerspriteCtrl = require("../controllers/sellerspriteCtrl");
const kindlerankerCtrl = require("../controllers/kindlerankerCtrl");
const iconscoutCtrl = require("../controllers/iconscoutCtrl");
const spinrewriterCtrl = require("../controllers/spinrewriterCtrl");
const pacdoraCtrl = require("../controllers/pacdoraCtrl");
const templatemonsterCtrl = require("../controllers/templatemonsterCtrl");
const indexmenowCtrl = require("../controllers/indexmenowCtrl");
const publicwwwCtrl = require("../controllers/publicwwwCtrl");
const searchatlasCtrl = require("../controllers/searchatlasCtrl");
const wincherCtrl = require("../controllers/wincherCtrl");

const proxyCtrl = require("../controllers/proxyCtrl");
const settingCtrl = require("../controllers/settingCtrl");
const siteCtrl = require("../controllers/siteCtrl");
const logCtrl = require("../controllers/logCtrl");
router.use("/authorize", authMiddleware, (req, res) => {
  res.status(301).redirect("/");
});

router.get("/api/proxies", proxyCtrl.getProxies);
router.get("/api/proxies/:id", proxyCtrl.getProxy);
router.post("/api/proxies", proxyCtrl.createProxy);
router.put("/api/proxies/:id", proxyCtrl.updateProxy);
router.delete("/api/proxies/:id", proxyCtrl.deleteProxy);

router.get("/api/setting", settingCtrl.getSetting);
router.post("/api/setting", settingCtrl.setSetting);

router.post("/api/semrush/login", semrushCtrl.login);
router.post("/api/spyfu/login", spyfuCtrl.login);
router.post("/api/seolyze/login", seolyzeCtrl.login);
router.post("/api/sistrix/login", sistrixCtrl.login);
router.post("/api/linkcentaur/login", linkcentaurCtrl.login);
router.post("/api/spamzilla/login", spamzillaCtrl.login);
router.post("/api/seodity/login", seodityCtrl.login);
router.post("/api/rytrme/login", rytrmeCtrl.login);
router.post("/api/wordai/login", wordaiCtrl.login);
router.post("/api/keyword/login", keywordCtrl.login);
router.post("/api/nichescraper/login", nichescraperCtrl.login);
router.post("/api/pipiads/login", pipiadsCtrl.login);
router.post("/api/keywordkeg/login", keywordkegCtrl.login);
router.post("/api/paraphraser/login", paraphraserCtrl.login);
router.post("/api/buzzsumo/login", buzzsumoCtrl.login);
router.post("/api/articleforge/login", articleforgeCtrl.login);
router.post("/api/bigspy/login", bigspyCtrl.login);
router.post("/api/colinkri/login", colinkriCtrl.login);
router.post("/api/dinorank/login", dinorankCtrl.login);
router.post("/api/yourtext/login", yourtextCtrl.login);
router.post("/api/babbar/login", babbarCtrl.login);
router.post("/api/firstfr/login", firstfrCtrl.login);
router.post("/api/textoptimizer/login", textoptimizerCtrl.login);
router.post("/api/onehourindexing/login", onehourindexingCtrl.login);
router.post("/api/ranxplorer/login", ranxplorerCtrl.login);
router.post("/api/woorank/login", woorankCtrl.login);
router.post("/api/seobserver/login", seobserverCtrl.login);
router.post("/api/seozoom/login", seozoomCtrl.login);
router.post("/api/affilisting/login", affilistingCtrl.login);
router.post("/api/explodingtopics/login", explodingtopicsCtrl.login);
router.post("/api/localranker/login", localrankerCtrl.login);
router.post("/api/prowritingaid/login", prowritingaidCtrl.login);
router.post("/api/copyscape/login", copyscapeCtrl.login);
router.post("/api/keywordcupid/login", keywordcupidCtrl.login);
router.post("/api/serpstat/login", serpstatCtrl.login);
router.post("/api/plagium/login", plagiumCtrl.login);
router.post("/api/closerscopy/login", closerscopyCtrl.login);
router.post("/api/linkody/login", linkodyCtrl.login);
router.post("/api/alishark/login", alisharkCtrl.login);
router.post("/api/pexda/login", pexdaCtrl.login);
router.post("/api/zonbase/login", zonbaseCtrl.login);
router.post("/api/dropship/login", dropshipCtrl.login);
router.post("/api/espinner/login", espinnerCtrl.login);
router.post("/api/asinseed/login", asinseedCtrl.login);
router.post("/api/sellersprite/login", sellerspriteCtrl.login);
router.post("/api/kindleranker/login", kindlerankerCtrl.login);
router.post("/api/iconscout/login", iconscoutCtrl.login);
router.post("/api/spinrewriter/login", spinrewriterCtrl.login);
router.post("/api/pacdora/login", pacdoraCtrl.login);
router.post("/api/templatemonster/login", templatemonsterCtrl.login);
router.post("/api/indexmenow/login", indexmenowCtrl.login);
router.post("/api/publicwww/login", publicwwwCtrl.login);
router.post("/api/searchatlas/login", searchatlasCtrl.login);
router.post("/api/wincher/login", wincherCtrl.login);

router.get("/api/sites", siteCtrl.getSites);
router.get("/api/sites/:id", siteCtrl.getSite);
router.post("/api/sites", siteCtrl.createSite);
router.put("/api/sites/:id", siteCtrl.updateSite);
router.delete("/api/sites/:id", siteCtrl.deleteSite);

router.get("/api/logs", logCtrl.getLogs);

router.get("/", adminMiddleware, (req, res) => res.render("index"));

module.exports = router;
