import express from "express";
import {
  finishRegistration,
  startRegistration,
  finishAuthentication,
  startAuthentication,
} from "../controllers/authController";

const router = express.Router();

router.post("/start-registration", startRegistration);
router.post("/verify-registration", finishRegistration);
router.post("/start-authentication", startAuthentication);
router.post("/verify-authentication", finishAuthentication);

export default router;
