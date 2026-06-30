# src/pii/anonymizer.py
import pandas as pd
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker
from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")


class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """
        Anonymize text với strategy được chọn.

        Strategies:
        - "mask"    : Nguyen Van A → N****** V** A
        - "replace" : thay bằng fake data (dùng Faker)
        - "hash"    : SHA-256 one-way hash
        - "generalize": chỉ dùng cho tuổi/năm sinh
        """
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        operators = {}

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace",
                          {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace",
                                 {"new_value": fake.email()}),
                "VN_CCCD": OperatorConfig("replace",
                           {"new_value": "".join([str(fake.random_int(min=0, max=9)) for _ in range(12)])}),
                "VN_PHONE": OperatorConfig("replace",
                            {"new_value": f"0{fake.random_int(min=3, max=9)}{fake.random_number(digits=8)}"}),
            }
        elif strategy == "mask":
            operators = {
                "PERSON": OperatorConfig("mask",
                          {"masking_char": "*", "chars_to_mask": 50, "from_end": False}),
                "EMAIL_ADDRESS": OperatorConfig("mask",
                                 {"masking_char": "*", "chars_to_mask": 50, "from_end": False}),
                "VN_CCCD": OperatorConfig("replace",
                           {"new_value": "************"}),
                "VN_PHONE": OperatorConfig("replace",
                            {"new_value": "0*********"}),
            }
        elif strategy == "hash":
            operators = {
                "PERSON": OperatorConfig("hash",
                          {"hash_type": "sha256"}),
                "EMAIL_ADDRESS": OperatorConfig("hash",
                                 {"hash_type": "sha256"}),
                "VN_CCCD": OperatorConfig("hash",
                           {"hash_type": "sha256"}),
                "VN_PHONE": OperatorConfig("hash",
                            {"hash_type": "sha256"}),
            }

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonymize toàn bộ DataFrame.
        - Cột text (ho_ten, dia_chi, email): dùng anonymize_text()
        - Cột cccd, so_dien_thoai: replace trực tiếp bằng fake data
        - Cột benh, ket_qua_xet_nghiem: GIỮ NGUYÊN (cần cho model training)
        - Cột patient_id: GIỮ NGUYÊN (pseudonym đã đủ an toàn)
        - Cột ngay_sinh, ngay_kham, bac_si_phu_trach: anonymize text
        """
        df_anon = df.copy()

        # Cột text: dùng anonymize_text()
        for col in ["ho_ten", "dia_chi", "email", "bac_si_phu_trach"]:
            if col in df_anon.columns:
                df_anon[col] = df_anon[col].apply(
                    lambda x: self.anonymize_text(str(x), strategy="replace")
                )

        # Cột CCCD: replace trực tiếp bằng fake CCCD
        if "cccd" in df_anon.columns:
            df_anon["cccd"] = df_anon["cccd"].apply(
                lambda x: "".join([str(fake.random_int(min=0, max=9)) for _ in range(12)])
            )

        # Cột số điện thoại: replace trực tiếp bằng fake SĐT
        if "so_dien_thoai" in df_anon.columns:
            df_anon["so_dien_thoai"] = df_anon["so_dien_thoai"].apply(
                lambda x: f"0{fake.random_int(min=3, max=9)}{fake.random_number(digits=8)}"
            )

        return df_anon

    def calculate_detection_rate(self,
                                  original_df: pd.DataFrame,
                                  pii_columns: list) -> float:
        """
        Tính % PII được detect thành công.
        Mục tiêu: > 95%
        """
        total = 0
        detected = 0

        for col in pii_columns:
            for value in original_df[col].astype(str):
                total += 1
                results = detect_pii(value, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0
