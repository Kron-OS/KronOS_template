--
-- PostgreSQL database dump
--

\restrict ASHrbndqytbHIKDFpZRoVtWfrvCzzgzz4H9bIUMmHj2u8vgqxTELzNWcCgWIKTl

-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    asset_id uuid NOT NULL,
    org_id uuid NOT NULL,
    hostname character varying(255) NOT NULL,
    hostname_lower character varying(255) NOT NULL,
    criticality character varying(64) NOT NULL,
    owner character varying(255),
    environment character varying(64),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: audit_anchor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_anchor (
    id bigint NOT NULL,
    org_id uuid,
    anchor_date date NOT NULL,
    root_hash character varying(64) NOT NULL,
    tsa_token bytea,
    event_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_anchor_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_anchor_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_anchor_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_anchor_id_seq OWNED BY public.audit_anchor.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    event_id uuid NOT NULL,
    event_type character varying(128) NOT NULL,
    actor_user_id uuid,
    actor_username character varying(256),
    org_id uuid NOT NULL,
    case_id uuid,
    evidence_id uuid,
    details json NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    sequence_number bigint NOT NULL,
    prev_row_hash character varying(64),
    row_hash character varying(64)
);


--
-- Name: cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cases (
    case_id uuid NOT NULL,
    org_id uuid NOT NULL,
    org_alias character varying(128) NOT NULL,
    owner_user_id uuid NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    reference_number character varying(255),
    classification character varying(64) DEFAULT 'UNCLASSIFIED'::character varying NOT NULL,
    status character varying(32) DEFAULT 'open'::character varying NOT NULL,
    member_user_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: dead_letter_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dead_letter_events (
    dead_letter_id uuid NOT NULL,
    org_id uuid NOT NULL,
    source_id character varying(256) NOT NULL,
    batch_id uuid NOT NULL,
    event_offset integer NOT NULL,
    payload bytea NOT NULL,
    error_type character varying(256) NOT NULL,
    error_message text NOT NULL,
    dead_lettered_at timestamp with time zone NOT NULL
);


--
-- Name: detection_correlations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_correlations (
    correlation_id uuid NOT NULL,
    org_id uuid NOT NULL,
    detection_id_a uuid NOT NULL,
    detection_id_b uuid NOT NULL,
    finding_id_a character varying(128) NOT NULL,
    finding_id_b character varying(128) NOT NULL,
    rule_ids text[] DEFAULT '{}'::text[] NOT NULL,
    synced_at timestamp with time zone NOT NULL
);


--
-- Name: detections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detections (
    detection_id uuid NOT NULL,
    org_id uuid NOT NULL,
    org_alias character varying(128) NOT NULL,
    case_id uuid,
    finding_id character varying(128) NOT NULL,
    detector_name character varying(256) NOT NULL,
    source_index character varying(512) NOT NULL,
    rule_matches json NOT NULL,
    matched_document_ids text[] DEFAULT '{}'::text[] NOT NULL,
    finding_timestamp timestamp with time zone NOT NULL,
    triage_state character varying(32) DEFAULT 'NEW'::character varying NOT NULL,
    synced_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    risk_score double precision,
    risk_factors json NOT NULL,
    external_ticket_id character varying(256)
);


--
-- Name: evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence (
    evidence_id uuid NOT NULL,
    org_id uuid NOT NULL,
    case_id uuid NOT NULL,
    org_alias character varying(128) NOT NULL,
    state character varying(32) NOT NULL,
    original_filename character varying(1024) NOT NULL,
    content_type character varying(256) NOT NULL,
    size_bytes bigint NOT NULL,
    uploader_user_id uuid NOT NULL,
    sha256 character varying(64),
    md5 character varying(32),
    minio_quarantine_key text,
    minio_evidence_key text,
    error_reason text,
    client_declared_sha256 character varying(64),
    legal_hold boolean DEFAULT false NOT NULL,
    object_lock_until timestamp with time zone,
    rfc3161_token bytea,
    quota_held boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: integration_source_cursors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_source_cursors (
    org_id uuid NOT NULL,
    source_id character varying NOT NULL,
    cursor_value character varying NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: ioc_feed_current_indicators; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feed_current_indicators (
    id bigint NOT NULL,
    feed_id uuid NOT NULL,
    org_id uuid NOT NULL,
    feed_name character varying(256) NOT NULL,
    ioc_type character varying(16) NOT NULL,
    value_normalized character varying(512) NOT NULL,
    indicator_json json NOT NULL
);


--
-- Name: ioc_feed_current_indicators_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.ioc_feed_current_indicators ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.ioc_feed_current_indicators_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: ioc_feed_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feed_versions (
    feed_id uuid NOT NULL,
    version integer NOT NULL,
    org_id uuid NOT NULL,
    source_format character varying(32) NOT NULL,
    indicators json NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: ioc_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feeds (
    feed_id uuid NOT NULL,
    org_id uuid NOT NULL,
    name character varying(256) NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: org_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_quotas (
    org_id uuid NOT NULL,
    storage_quota_bytes bigint,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: published_custom_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_custom_rules (
    rule_id uuid NOT NULL,
    org_id uuid NOT NULL,
    opensearch_rule_id character varying(128) NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: rule_pack_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_pack_versions (
    pack_id uuid NOT NULL,
    version integer NOT NULL,
    org_id uuid NOT NULL,
    source_tier character varying(32) NOT NULL,
    rules json NOT NULL,
    signature_verified boolean NOT NULL,
    content_sha256 character varying(64),
    created_at timestamp with time zone NOT NULL
);


--
-- Name: rule_packs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_packs (
    pack_id uuid NOT NULL,
    org_id uuid NOT NULL,
    name character varying(256) NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: sealed_batches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sealed_batches (
    batch_id uuid NOT NULL,
    org_id uuid NOT NULL,
    source_id character varying(256) NOT NULL,
    sealed_at timestamp with time zone NOT NULL,
    event_count integer NOT NULL,
    leaf_hashes json NOT NULL,
    message_ids json NOT NULL,
    merkle_root character varying(64) NOT NULL,
    worm_bucket character varying(256) NOT NULL,
    worm_object_key character varying(1024) NOT NULL,
    tsa_token bytea,
    first_message_id character varying(64) NOT NULL,
    last_message_id character varying(64) NOT NULL
);


--
-- Name: structured_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.structured_artifacts (
    artifact_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    case_id uuid NOT NULL,
    org_id uuid NOT NULL,
    kind character varying(255) NOT NULL,
    sha256 character varying(64) NOT NULL,
    parser character varying(128) NOT NULL,
    parser_version character varying(64) NOT NULL,
    source_path text,
    container_sha256 character varying(64),
    record_index integer NOT NULL,
    content jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: yara_rule_pack_published; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.yara_rule_pack_published (
    pack_id uuid NOT NULL,
    version integer NOT NULL,
    org_id uuid NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: yara_rule_pack_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.yara_rule_pack_versions (
    pack_id uuid NOT NULL,
    version integer NOT NULL,
    org_id uuid NOT NULL,
    source_tier character varying(32) NOT NULL,
    rules json NOT NULL,
    signature_verified boolean NOT NULL,
    content_sha256 character varying(64),
    created_at timestamp with time zone NOT NULL
);


--
-- Name: yara_rule_packs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.yara_rule_packs (
    pack_id uuid NOT NULL,
    org_id uuid NOT NULL,
    name character varying(256) NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: audit_anchor id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_anchor ALTER COLUMN id SET DEFAULT nextval('public.audit_anchor_id_seq'::regclass);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (asset_id);


--
-- Name: audit_anchor audit_anchor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_anchor
    ADD CONSTRAINT audit_anchor_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (event_id);


--
-- Name: cases cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (case_id);


--
-- Name: dead_letter_events dead_letter_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_events
    ADD CONSTRAINT dead_letter_events_pkey PRIMARY KEY (dead_letter_id);


--
-- Name: detection_correlations detection_correlations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_correlations
    ADD CONSTRAINT detection_correlations_pkey PRIMARY KEY (correlation_id);


--
-- Name: detections detections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT detections_pkey PRIMARY KEY (detection_id);


--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (evidence_id);


--
-- Name: integration_source_cursors integration_source_cursors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_source_cursors
    ADD CONSTRAINT integration_source_cursors_pkey PRIMARY KEY (org_id, source_id);


--
-- Name: ioc_feed_current_indicators ioc_feed_current_indicators_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_current_indicators
    ADD CONSTRAINT ioc_feed_current_indicators_pkey PRIMARY KEY (id);


--
-- Name: ioc_feeds ioc_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feeds
    ADD CONSTRAINT ioc_feeds_pkey PRIMARY KEY (feed_id);


--
-- Name: org_quotas org_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_quotas
    ADD CONSTRAINT org_quotas_pkey PRIMARY KEY (org_id);


--
-- Name: ioc_feed_versions pk_ioc_feed_versions; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_versions
    ADD CONSTRAINT pk_ioc_feed_versions PRIMARY KEY (feed_id, version);


--
-- Name: rule_pack_versions pk_rule_pack_versions; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_pack_versions
    ADD CONSTRAINT pk_rule_pack_versions PRIMARY KEY (pack_id, version);


--
-- Name: yara_rule_pack_versions pk_yara_rule_pack_versions; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_rule_pack_versions
    ADD CONSTRAINT pk_yara_rule_pack_versions PRIMARY KEY (pack_id, version);


--
-- Name: published_custom_rules published_custom_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_custom_rules
    ADD CONSTRAINT published_custom_rules_pkey PRIMARY KEY (rule_id);


--
-- Name: rule_packs rule_packs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_packs
    ADD CONSTRAINT rule_packs_pkey PRIMARY KEY (pack_id);


--
-- Name: sealed_batches sealed_batches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sealed_batches
    ADD CONSTRAINT sealed_batches_pkey PRIMARY KEY (batch_id);


--
-- Name: structured_artifacts structured_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.structured_artifacts
    ADD CONSTRAINT structured_artifacts_pkey PRIMARY KEY (artifact_id);


--
-- Name: assets uq_assets_org_hostname; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT uq_assets_org_hostname UNIQUE (org_id, hostname_lower);


--
-- Name: audit_anchor uq_audit_anchor_org_date; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_anchor
    ADD CONSTRAINT uq_audit_anchor_org_date UNIQUE (org_id, anchor_date);


--
-- Name: audit_log uq_audit_log_org_seq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT uq_audit_log_org_seq UNIQUE (org_id, sequence_number);


--
-- Name: detections uq_detections_org_finding; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detections
    ADD CONSTRAINT uq_detections_org_finding UNIQUE (org_id, finding_id);


--
-- Name: ioc_feeds uq_ioc_feeds_org_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feeds
    ADD CONSTRAINT uq_ioc_feeds_org_name UNIQUE (org_id, name);


--
-- Name: rule_packs uq_rule_packs_org_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_packs
    ADD CONSTRAINT uq_rule_packs_org_name UNIQUE (org_id, name);


--
-- Name: yara_rule_packs uq_yara_rule_packs_org_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_rule_packs
    ADD CONSTRAINT uq_yara_rule_packs_org_name UNIQUE (org_id, name);


--
-- Name: yara_rule_pack_published yara_rule_pack_published_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_rule_pack_published
    ADD CONSTRAINT yara_rule_pack_published_pkey PRIMARY KEY (pack_id);


--
-- Name: yara_rule_packs yara_rule_packs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_rule_packs
    ADD CONSTRAINT yara_rule_packs_pkey PRIMARY KEY (pack_id);


--
-- Name: ix_assets_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_assets_org_id ON public.assets USING btree (org_id);


--
-- Name: ix_audit_anchor_anchor_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_anchor_anchor_date ON public.audit_anchor USING btree (anchor_date);


--
-- Name: ix_audit_anchor_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_anchor_org_id ON public.audit_anchor USING btree (org_id);


--
-- Name: ix_audit_log_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_case_id ON public.audit_log USING btree (case_id);


--
-- Name: ix_audit_log_evidence_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_evidence_id ON public.audit_log USING btree (evidence_id);


--
-- Name: ix_audit_log_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_org_id ON public.audit_log USING btree (org_id);


--
-- Name: ix_cases_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_cases_org_id ON public.cases USING btree (org_id);


--
-- Name: ix_dead_letter_events_batch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_dead_letter_events_batch_id ON public.dead_letter_events USING btree (batch_id);


--
-- Name: ix_dead_letter_events_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_dead_letter_events_org_id ON public.dead_letter_events USING btree (org_id);


--
-- Name: ix_dead_letter_events_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_dead_letter_events_source_id ON public.dead_letter_events USING btree (source_id);


--
-- Name: ix_detection_correlations_detection_id_a; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_detection_correlations_detection_id_a ON public.detection_correlations USING btree (detection_id_a);


--
-- Name: ix_detection_correlations_detection_id_b; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_detection_correlations_detection_id_b ON public.detection_correlations USING btree (detection_id_b);


--
-- Name: ix_detection_correlations_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_detection_correlations_org_id ON public.detection_correlations USING btree (org_id);


--
-- Name: ix_detections_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_detections_case_id ON public.detections USING btree (case_id);


--
-- Name: ix_detections_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_detections_org_id ON public.detections USING btree (org_id);


--
-- Name: ix_evidence_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_case_id ON public.evidence USING btree (case_id);


--
-- Name: ix_evidence_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_org_id ON public.evidence USING btree (org_id);


--
-- Name: ix_ioc_current_match; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ioc_current_match ON public.ioc_feed_current_indicators USING btree (org_id, ioc_type, value_normalized);


--
-- Name: ix_ioc_feed_current_indicators_feed_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ioc_feed_current_indicators_feed_id ON public.ioc_feed_current_indicators USING btree (feed_id);


--
-- Name: ix_ioc_feed_versions_feed_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ioc_feed_versions_feed_id ON public.ioc_feed_versions USING btree (feed_id);


--
-- Name: ix_ioc_feed_versions_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ioc_feed_versions_org_id ON public.ioc_feed_versions USING btree (org_id);


--
-- Name: ix_ioc_feeds_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ioc_feeds_org_id ON public.ioc_feeds USING btree (org_id);


--
-- Name: ix_published_custom_rules_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_published_custom_rules_org_id ON public.published_custom_rules USING btree (org_id);


--
-- Name: ix_rule_pack_versions_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_pack_versions_org_id ON public.rule_pack_versions USING btree (org_id);


--
-- Name: ix_rule_pack_versions_pack_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_pack_versions_pack_id ON public.rule_pack_versions USING btree (pack_id);


--
-- Name: ix_rule_packs_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_packs_org_id ON public.rule_packs USING btree (org_id);


--
-- Name: ix_sealed_batches_last_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sealed_batches_last_message_id ON public.sealed_batches USING btree (last_message_id);


--
-- Name: ix_sealed_batches_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sealed_batches_org_id ON public.sealed_batches USING btree (org_id);


--
-- Name: ix_sealed_batches_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sealed_batches_source_id ON public.sealed_batches USING btree (source_id);


--
-- Name: ix_structured_artifacts_case_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_structured_artifacts_case_id ON public.structured_artifacts USING btree (case_id);


--
-- Name: ix_structured_artifacts_evidence_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_structured_artifacts_evidence_id ON public.structured_artifacts USING btree (evidence_id);


--
-- Name: ix_structured_artifacts_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_structured_artifacts_kind ON public.structured_artifacts USING btree (kind);


--
-- Name: ix_structured_artifacts_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_structured_artifacts_org_id ON public.structured_artifacts USING btree (org_id);


--
-- Name: ix_yara_rule_pack_published_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_yara_rule_pack_published_org_id ON public.yara_rule_pack_published USING btree (org_id);


--
-- Name: ix_yara_rule_pack_versions_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_yara_rule_pack_versions_org_id ON public.yara_rule_pack_versions USING btree (org_id);


--
-- Name: ix_yara_rule_pack_versions_pack_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_yara_rule_pack_versions_pack_id ON public.yara_rule_pack_versions USING btree (pack_id);


--
-- Name: ix_yara_rule_packs_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_yara_rule_packs_org_id ON public.yara_rule_packs USING btree (org_id);


--
-- PostgreSQL database dump complete
--

\unrestrict ASHrbndqytbHIKDFpZRoVtWfrvCzzgzz4H9bIUMmHj2u8vgqxTELzNWcCgWIKTl

