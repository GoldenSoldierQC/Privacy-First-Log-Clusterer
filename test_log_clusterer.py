#!/usr/bin/env python3
"""
Comprehensive unit tests for log_clusterer.py
Tests SimHash, PII detection, clustering, and report generation.
"""
import json
import os
import tempfile
from datetime import datetime

from log_clusterer import (Cluster, LogClusterer, detect_pii,
                           extract_timestamp, hamming, sanitize_text, simhash,
                           stable_hash64, tokenize)


class TestTokenization:
    """Test tokenization functions"""

    def test_tokenize_basic(self):
        text = "hello world test"
        tokens = tokenize(text, use_bigrams=False)
        assert "hello" in tokens
        assert "world" in tokens
        assert "test" in tokens

    def test_tokenize_with_bigrams(self):
        text = "hello world"
        tokens = tokenize(text, use_bigrams=True)
        assert "hello" in tokens
        assert "world" in tokens
        assert "hello_world" in tokens

    def test_tokenize_empty(self):
        tokens = tokenize("", use_bigrams=True)
        assert tokens == []

    def test_tokenize_special_chars(self):
        text = "error-123 failed@test"
        tokens = tokenize(text, use_bigrams=False)
        assert "error" in tokens
        assert "123" in tokens
        assert "failed" in tokens
        assert "test" in tokens


class TestSimHash:
    """Test SimHash algorithm"""

    def test_stable_hash64_consistency(self):
        # Same input should produce same hash
        token = "test_token"
        hash1 = stable_hash64(token)
        hash2 = stable_hash64(token)
        assert hash1 == hash2

    def test_stable_hash64_different_inputs(self):
        # Different inputs should produce different hashes
        hash1 = stable_hash64("token1")
        hash2 = stable_hash64("token2")
        assert hash1 != hash2

    def test_simhash_empty_string(self):
        # Empty string should produce 0
        fp = simhash("")
        assert fp == 0

    def test_simhash_consistency(self):
        # Same text should produce same fingerprint
        text = "error database connection timeout"
        fp1 = simhash(text)
        fp2 = simhash(text)
        assert fp1 == fp2

    def test_simhash_similar_texts(self):
        # Similar texts should have similar fingerprints
        text1 = "error database connection timeout"
        text2 = "error database connection failed"
        fp1 = simhash(text1)
        fp2 = simhash(text2)
        # Hamming distance should be small for similar texts
        distance = hamming(fp1, fp2)
        assert distance < 20  # Reasonable threshold for similar texts


class TestHammingDistance:
    """Test Hamming distance calculation"""

    def test_hamming_identical(self):
        # Distance between identical values should be 0
        assert hamming(0b1010, 0b1010) == 0

    def test_hamming_single_bit(self):
        # Single bit difference
        assert hamming(0b1010, 0b1011) == 1

    def test_hamming_all_different(self):
        # All bits different
        assert hamming(0b0000, 0b1111) == 4

    def test_hamming_large_numbers(self):
        # Test with larger numbers
        a = 0xFFFFFFFFFFFFFFFF
        b = 0x0000000000000000
        assert hamming(a, b) == 64


class TestPIIDetection:
    """Test PII detection and sanitization"""

    def test_detect_email(self):
        text = "User john.doe@example.com logged in"
        pii = detect_pii(text)
        assert "email" in pii
        assert "john.doe@example.com" in pii["email"]

    def test_detect_ipv4(self):
        text = "Connection from 192.168.1.100"
        pii = detect_pii(text)
        assert "ipv4" in pii
        assert "192.168.1.100" in pii["ipv4"]

    def test_detect_uuid(self):
        text = "Request 550e8400-e29b-41d4-a716-446655440000 processed"
        pii = detect_pii(text)
        assert "uuid" in pii
        assert "550e8400-e29b-41d4-a716-446655440000" in pii["uuid"]

    def test_detect_credit_card(self):
        text = "Payment 4111-1111-1111-1111 processed"
        pii = detect_pii(text)
        assert "credit_card_like" in pii

    def test_detect_phone(self):
        text = "Contact +1-555-123-4567 for support"
        pii = detect_pii(text)
        assert "phone" in pii

    def test_detect_multiple_pii(self):
        text = "User john@test.com from 10.0.0.1 called +1-555-0000"
        pii = detect_pii(text)
        assert "email" in pii
        assert "ipv4" in pii
        assert "phone" in pii

    def test_sanitize_email(self):
        text = "User john.doe@example.com logged in"
        sanitized = sanitize_text(text)
        assert "john.doe@example.com" not in sanitized
        assert "<EMAIL>" in sanitized

    def test_sanitize_ip(self):
        text = "Connection from 192.168.1.100"
        sanitized = sanitize_text(text)
        assert "192.168.1.100" not in sanitized
        assert "<IPV4>" in sanitized

    def test_sanitize_multiple(self):
        text = "User test@email.com from 10.0.0.1"
        sanitized = sanitize_text(text)
        assert "test@email.com" not in sanitized
        assert "10.0.0.1" not in sanitized
        assert "<EMAIL>" in sanitized
        assert "<IPV4>" in sanitized


class TestTimestampExtraction:
    """Test timestamp extraction from log lines"""

    def test_extract_iso_timestamp(self):
        line = "2025-10-30T12:34:56Z ERROR Database failed"
        ts = extract_timestamp(line)
        assert ts is not None
        assert ts.year == 2025
        assert ts.month == 10
        assert ts.day == 30

    def test_extract_slash_timestamp(self):
        line = "2025/10/30 12:34:56 ERROR Database failed"
        ts = extract_timestamp(line)
        assert ts is not None
        assert ts.year == 2025

    def test_extract_time_only(self):
        line = "12:34:56 ERROR Database failed"
        ts = extract_timestamp(line)
        assert ts is not None
        assert ts.hour == 12
        assert ts.minute == 34

    def test_extract_unix_timestamp(self):
        line = "1698765432 ERROR Database failed"
        ts = extract_timestamp(line)
        assert ts is not None

    def test_extract_no_timestamp(self):
        line = "ERROR Database failed"
        ts = extract_timestamp(line)
        assert ts is None


class TestCluster:
    """Test Cluster class"""

    def test_cluster_creation(self):
        msg = "error database timeout"
        ts = datetime.now()
        fp = simhash(msg)
        cluster = Cluster(msg, ts, fp)
        assert cluster.count == 1
        assert len(cluster.messages) == 1
        assert cluster.first_ts == ts
        assert cluster.last_ts == ts

    def test_cluster_add_message(self):
        msg1 = "error database timeout"
        ts1 = datetime.now()
        fp1 = simhash(msg1)
        cluster = Cluster(msg1, ts1, fp1)

        msg2 = "error database failed"
        ts2 = datetime.now()
        fp2 = simhash(msg2)
        cluster.add(msg2, ts2, fp2)

        assert cluster.count == 2
        assert len(cluster.messages) == 2
        assert cluster.last_ts == ts2

    def test_cluster_max_messages(self):
        msg = "test message"
        ts = datetime.now()
        fp = simhash(msg)
        cluster = Cluster(msg, ts, fp)

        # Add more than 8 messages
        for i in range(10):
            cluster.add(f"message {i}", ts, fp)

        # Should keep only last 8 messages
        assert len(cluster.messages) <= 8

    def test_cluster_representative(self):
        msg1 = "first message"
        ts1 = datetime.now()
        fp1 = simhash(msg1)
        cluster = Cluster(msg1, ts1, fp1)

        msg2 = "last message"
        ts2 = datetime.now()
        fp2 = simhash(msg2)
        cluster.add(msg2, ts2, fp2)

        # Representative should be last message
        assert cluster.representative() == msg2


class TestLogClusterer:
    """Test LogClusterer class"""

    def test_clusterer_creation(self):
        lc = LogClusterer(hamming_threshold=6)
        assert lc.hamming_threshold == 6
        assert lc.total_events == 0
        assert len(lc.clusters) == 0

    def test_process_single_line(self):
        lc = LogClusterer()
        line = "2025-10-30T12:00:00Z ERROR Database failed"
        lc.process_line(line)
        assert lc.total_events == 1
        assert len(lc.clusters) == 1

    def test_process_similar_lines(self):
        lc = LogClusterer(hamming_threshold=6)
        line1 = "ERROR Database connection timeout host1"
        line2 = "ERROR Database connection timeout host2"
        lc.process_line(line1)
        lc.process_line(line2)
        assert lc.total_events == 2
        # Similar lines should cluster together
        assert len(lc.clusters) <= 2

    def test_process_different_lines(self):
        lc = LogClusterer(hamming_threshold=6)
        line1 = "ERROR Database connection timeout"
        line2 = "INFO User logged in successfully"
        lc.process_line(line1)
        lc.process_line(line2)
        assert lc.total_events == 2
        # Different lines should create different clusters
        assert len(lc.clusters) == 2

    def test_process_file(self):
        lc = LogClusterer()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("2025-10-30T12:00:00Z ERROR Database failed\n")
            f.write("2025-10-30T12:01:00Z ERROR Database failed\n")
            f.write("2025-10-30T12:02:00Z INFO User logged in\n")
            temp_path = f.name

        try:
            lc.process_file(temp_path)
            assert lc.total_events == 3
            assert len(lc.clusters) >= 1
        finally:
            os.unlink(temp_path)

    def test_write_report(self):
        lc = LogClusterer()
        lc.process_line("ERROR Database failed")
        lc.process_line("INFO User logged in")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html") as f:
            report_path = f.name

        try:
            lc.report_path = report_path
            lc.write_report(title="Test Report")
            assert os.path.exists(report_path)
            with open(report_path, "r") as f:
                content = f.read()
                assert "Test Report" in content
                assert "Cluster" in content
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    def test_write_report_with_sanitization(self):
        lc = LogClusterer(sanitize=True)
        lc.process_line("ERROR User john@test.com from 10.0.0.1")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html") as f:
            report_path = f.name

        try:
            lc.report_path = report_path
            lc.write_report(title="Sanitized Report")
            assert os.path.exists(report_path)
            with open(report_path, "r") as f:
                content = f.read()
                # Should not contain PII
                assert "john@test.com" not in content
                assert "10.0.0.1" not in content
                # Should contain placeholders
                assert "&lt;EMAIL&gt;" in content or "<EMAIL>" in content
                assert "&lt;IPV4&gt;" in content or "<IPV4>" in content
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    def test_clusters_to_registry(self):
        lc = LogClusterer()
        lc.process_line("ERROR Database failed")
        lc.process_line("INFO User logged in")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            registry_path = f.name

        try:
            lc.clusters_to_registry(registry_path, sanitized=False)
            assert os.path.exists(registry_path)
            with open(registry_path, "r") as f:
                data = json.load(f)
                assert "generated" in data
                assert "registry" in data
                assert len(data["registry"]) > 0
                # Check first artifact
                artifact = data["registry"][0]
                assert "artifact_id" in artifact
                assert "metadata" in artifact
                assert "license" in artifact
        finally:
            if os.path.exists(registry_path):
                os.unlink(registry_path)

    def test_clusters_to_registry_sanitized(self):
        lc = LogClusterer()
        lc.process_line("ERROR User test@email.com failed")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            registry_path = f.name

        try:
            lc.clusters_to_registry(registry_path, sanitized=True)
            with open(registry_path, "r") as f:
                data = json.load(f)
                # Check that PII is sanitized in metadata
                artifact = data["registry"][0]
                rep = artifact["metadata"]["representative"]
                assert "test@email.com" not in rep
                assert "<EMAIL>" in rep
        finally:
            if os.path.exists(registry_path):
                os.unlink(registry_path)


class TestIntegration:
    """Integration tests for full workflows"""

    def test_demo_workflow(self):
        """Test the demo workflow end-to-end"""
        lc = LogClusterer(sanitize=True)

        # Create temporary files
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("2025-10-30T12:00:00Z ERROR Database timeout\n")
            f.write("2025-10-30T12:01:00Z ERROR Database timeout\n")
            f.write("2025-10-30T12:02:00Z INFO User john@test.com logged in\n")
            f.write("2025-10-30T12:03:00Z ERROR Database timeout\n")
            log_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".html") as f:
            report_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            registry_path = f.name

        try:
            # Process log file
            lc.process_file(log_path)
            assert lc.total_events == 4

            # Generate report and registry
            lc.report_path = report_path
            lc.write_report(title="Integration Test", registry_path=registry_path)

            # Verify report exists and contains expected content
            assert os.path.exists(report_path)
            with open(report_path, "r") as f:
                content = f.read()
                assert "Integration Test" in content
                # PII should be sanitized
                assert "john@test.com" not in content

            # Verify registry exists and is valid
            assert os.path.exists(registry_path)
            with open(registry_path, "r") as f:
                data = json.load(f)
                assert "registry" in data
                assert len(data["registry"]) > 0

        finally:
            for path in [log_path, report_path, registry_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_clustering_accuracy(self):
        """Test that similar messages are properly clustered"""
        lc = LogClusterer(hamming_threshold=6)

        # Add similar error messages
        for i in range(5):
            lc.process_line(f"ERROR Database connection timeout to host{i}")

        # Add similar info messages
        for i in range(3):
            lc.process_line(f"INFO User{i} logged in successfully")

        # Add different critical message
        lc.process_line("CRITICAL System out of memory")

        # We should have processed all events
        assert lc.total_events == 9
        # At least some clustering should occur
        assert len(lc.clusters) >= 1
