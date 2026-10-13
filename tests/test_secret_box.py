# -*- coding: utf-8 -*-
"""
secret_box 凭据静态加密回归（2026-10-13）
覆盖：DPAPI 往返 / 防双重加密 / 透明层落盘密文读出明文 / 解密失败回退 /
      migrate 幂等 / save_cred 身份语义在加密下不破坏。
DPAPI 专属用例在非 Windows（CI ubuntu）自动跳过。
"""
import json
import os
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import cred_store as cs     # noqa: E402
import secret_box as sb     # noqa: E402

HAS_DPAPI = sb._protect is not None and os.name == "nt"


class ValueRoundTripTest(unittest.TestCase):
    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI")
    def test_protect_unprotect_roundtrip(self):
        v = "sk-live-abc123中文"
        e = sb.protect_value(v)
        self.assertTrue(e.startswith("dpapi:"))
        self.assertNotIn("sk-live", e)
        self.assertEqual(sb.unprotect_value(e), v)

    def test_empty_and_nonstr_passthrough(self):
        self.assertEqual(sb.protect_value(""), "")
        self.assertEqual(sb.protect_value(None), None)
        self.assertEqual(sb.unprotect_value("plain-token"), "plain-token")

    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI")
    def test_no_double_encrypt(self):
        once = sb.protect_value("tok")
        self.assertEqual(sb.protect_value(once), once, "已加密值不得二次加密")

    def test_decrypt_failure_returns_original(self):
        fake = "dpapi:AAAA-not-real-base64!!"
        self.assertEqual(sb.unprotect_value(fake), fake,
                         "解密失败必须返回原值（401 暴露问题），不得抛异常")


class ObjectWalkTest(unittest.TestCase):
    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI（非 Windows 加密为透传，无密文可断言）")
    def test_encrypt_only_secret_fields(self):
        obj = {"user_id": "u1", "phone": "138", "access_token": "at-xyz",
               "list": [{"refresh_token": "rt-1"}, "keepme"]}
        enc = sb.encrypt_obj(obj)
        self.assertEqual(enc["user_id"], "u1")
        self.assertEqual(enc["phone"], "138")
        self.assertNotEqual(enc["access_token"], "at-xyz")
        self.assertNotEqual(enc["list"][0]["refresh_token"], "rt-1")
        self.assertEqual(enc["list"][1], "keepme")

    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI")
    def test_full_roundtrip(self):
        obj = {"token": "t1", "user_id": "u1", "sk": "s1"}
        self.assertEqual(sb.decrypt_obj(sb.encrypt_obj(obj)),
                         {"token": "t1", "user_id": "u1", "sk": "s1"})


class CredStoreTransparentTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="secbox_")
        self.path = os.path.join(self.dir, "m_accounts.json")

    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI")
    def test_write_encrypted_on_disk_read_plaintext(self):
        cs.write_json(self.path, {"user_id": "u1", "access_token": "secret-at"})
        raw = open(self.path, encoding="utf-8").read()
        self.assertIn("dpapi:", raw, "磁盘上 token 必须是密文")
        self.assertNotIn("secret-at", raw)
        self.assertIn("u1", raw, "身份字段保持明文")
        got = cs.read_json(self.path, {})
        self.assertEqual(got["access_token"], "secret-at")

    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI")
    def test_save_cred_identity_semantics_with_encryption(self):
        cf = {"minimax": self.path}
        k1 = cs.save_cred("minimax", {"user_id": "u1", "access_token": "a1"}, "小柴", cf)
        k2 = cs.save_cred("minimax", {"user_id": "u1", "access_token": "a2"}, "小柴", cf)
        self.assertEqual(k1, k2, "加密不得破坏「同身份沿用键名」语义")
        data = cs.read_json(self.path, {})
        self.assertEqual(data[k2]["access_token"], "a2")


class UtilHelperTest(unittest.TestCase):
    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI")
    def test_util_dec_enc_roundtrip(self):
        from platforms._util import dec_cred, enc_cred
        obj = {"cookie": "BDUSS=xxx", "user_id": "u9"}
        self.assertEqual(dec_cred(enc_cred(obj)), obj)


class MigrateTest(unittest.TestCase):
    @unittest.skipUnless(HAS_DPAPI, "需要 Windows DPAPI（非 Windows 加密为透传，无密文可断言）")
    def test_migrate_and_idempotent(self):
        d = tempfile.mkdtemp(prefix="secbox_mig_")
        p = os.path.join(d, "x_accounts.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"token": "plain-tok", "user_id": "u1"}, f)
        files, fields = sb.migrate_dir(d)
        self.assertEqual((files, fields), (1, 1))
        self.assertTrue(os.path.exists(p + ".bak-preenc"), "迁移前必须落 .bak 备份")
        raw = open(p, encoding="utf-8").read()
        self.assertIn("dpapi:", raw)
        # 幂等：二次迁移应零变更
        files2, fields2 = sb.migrate_dir(d)
        self.assertEqual((files2, fields2), (0, 0))


if __name__ == "__main__":
    unittest.main()


class FetchStateDecryptTest(unittest.TestCase):
    """回归：fetch_state._from_file 必须解密 wb_login_result.json 的 DPAPI 字段。

    2026-10-13 事故：加密迁移漏了 WorkBuddy 链路（fetch_state 裸 json.load），
    看板 WorkBuddy 全部账号「状态未知」。新凭据文件接入时必须走解密读。
    """

    def test_from_file_decrypts_dpapi_fields(self):
        import json, os, sys, tempfile
        sys.path.insert(0, os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), "src"))
        import secret_box
        import fetch_state
        d = tempfile.mkdtemp(prefix="wb_dec_")
        p = os.path.join(d, "wb_login_result.json")
        # wb_login_result.json 是 list 格式（workbuddy_login.py 写出）
        ent = [{"phone": "13800000000",
                "access_token": "eyJhbGciOi.fake.at", "refresh_token": "rt-plain"}]
        with open(p, "w", encoding="utf-8") as f:
            json.dump(secret_box.encrypt_obj(ent), f, ensure_ascii=False)
        got = fetch_state._from_file(p)
        self.assertEqual(got.get("13800000000", {}).get("access_token"),
                         "eyJhbGciOi.fake.at")
        self.assertEqual(got.get("13800000000", {}).get("refresh_token"), "rt-plain")

    def test_from_file_decrypts_dict_format(self):
        """dict 格式（wb_refresh_tokens.json，L0NE-6 主脚本）同样要解密。"""
        import json, os, sys, tempfile
        sys.path.insert(0, os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), "src"))
        import secret_box
        import fetch_state
        d = tempfile.mkdtemp(prefix="wb_dec_d_")
        p = os.path.join(d, "wb_refresh_tokens.json")
        raw = {"13911111111": {"access_token": "at-enc", "refresh_token": "rt-enc"}}
        with open(p, "w", encoding="utf-8") as f:
            json.dump(secret_box.encrypt_obj(raw), f, ensure_ascii=False)
        got = fetch_state._from_file(p)
        self.assertEqual(got.get("13911111111", {}).get("access_token"), "at-enc")
        self.assertEqual(got.get("13911111111", {}).get("refresh_token"), "rt-enc")

    def test_from_file_plain_file_still_works(self):
        import json, os, sys, tempfile
        sys.path.insert(0, os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), "src"))
        import fetch_state
        d = tempfile.mkdtemp(prefix="wb_plain_")
        p = os.path.join(d, "wb_refresh_tokens.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"13911111111": {"access_token": "at-x", "refresh_token": "rt-y"}},
                      f, ensure_ascii=False)
        got = fetch_state._from_file(p)
        self.assertEqual(got.get("13911111111", {}).get("access_token"), "at-x")
