--
-- PostgreSQL database dump
--

-- Dumped from database version 11.2
-- Dumped by pg_dump version 11.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64)
);


ALTER TABLE public.admin_event_entity OWNER TO keycloak;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO keycloak;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO keycloak;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO keycloak;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO keycloak;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO keycloak;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO keycloak;

--
-- Name: client; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO keycloak;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    value character varying(4000),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_attributes OWNER TO keycloak;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO keycloak;

--
-- Name: client_default_roles; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_default_roles (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_default_roles OWNER TO keycloak;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO keycloak;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO keycloak;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO keycloak;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO keycloak;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope_client (
    client_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO keycloak;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO keycloak;

--
-- Name: client_session; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_session (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    redirect_uri character varying(255),
    state character varying(255),
    "timestamp" integer,
    session_id character varying(36),
    auth_method character varying(255),
    realm_id character varying(255),
    auth_user_id character varying(36),
    current_action character varying(36)
);


ALTER TABLE public.client_session OWNER TO keycloak;

--
-- Name: client_session_auth_status; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_session_auth_status (
    authenticator character varying(36) NOT NULL,
    status integer,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_auth_status OWNER TO keycloak;

--
-- Name: client_session_note; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_session_note (
    name character varying(255) NOT NULL,
    value character varying(255),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_note OWNER TO keycloak;

--
-- Name: client_session_prot_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_session_prot_mapper (
    protocol_mapper_id character varying(36) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_prot_mapper OWNER TO keycloak;

--
-- Name: client_session_role; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_session_role (
    role_id character varying(255) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_role OWNER TO keycloak;

--
-- Name: client_user_session_note; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_user_session_note (
    name character varying(255) NOT NULL,
    value character varying(2048),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_user_session_note OWNER TO keycloak;

--
-- Name: component; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO keycloak;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.component_config OWNER TO keycloak;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO keycloak;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(4000),
    user_id character varying(36),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT NULL::character varying
);


ALTER TABLE public.credential OWNER TO keycloak;

--
-- Name: credential_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.credential_attribute OWNER TO keycloak;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO keycloak;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO keycloak;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO keycloak;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255)
);


ALTER TABLE public.event_entity OWNER TO keycloak;

--
-- Name: fed_credential_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.fed_credential_attribute OWNER TO keycloak;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024)
);


ALTER TABLE public.fed_user_attribute OWNER TO keycloak;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO keycloak;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO keycloak;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(255),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT 'HmacSHA1'::character varying,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_credential OWNER TO keycloak;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO keycloak;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO keycloak;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO keycloak;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO keycloak;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO keycloak;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO keycloak;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO keycloak;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean DEFAULT false NOT NULL,
    authenticate_by_default boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    add_token_role boolean DEFAULT true NOT NULL,
    trust_email boolean DEFAULT false NOT NULL,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean DEFAULT false NOT NULL
);


ALTER TABLE public.identity_provider OWNER TO keycloak;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO keycloak;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO keycloak;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO keycloak;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36),
    realm_id character varying(36)
);


ALTER TABLE public.keycloak_group OWNER TO keycloak;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(36),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO keycloak;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36)
);


ALTER TABLE public.migration_model OWNER TO keycloak;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(36) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL
);


ALTER TABLE public.offline_client_session OWNER TO keycloak;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.offline_user_session OWNER TO keycloak;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO keycloak;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO keycloak;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO keycloak;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.realm OWNER TO keycloak;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_attribute OWNER TO keycloak;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO keycloak;

--
-- Name: realm_default_roles; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_default_roles (
    realm_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_roles OWNER TO keycloak;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO keycloak;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO keycloak;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO keycloak;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO keycloak;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO keycloak;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO keycloak;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO keycloak;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO keycloak;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO keycloak;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO keycloak;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO keycloak;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode character varying(15) NOT NULL,
    decision_strategy smallint DEFAULT 1 NOT NULL
);


ALTER TABLE public.resource_server OWNER TO keycloak;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(36) NOT NULL,
    requester character varying(36) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO keycloak;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy character varying(20),
    logic character varying(20),
    resource_server_id character varying(36) NOT NULL,
    owner character varying(36)
);


ALTER TABLE public.resource_server_policy OWNER TO keycloak;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(36) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO keycloak;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO keycloak;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO keycloak;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO keycloak;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO keycloak;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO keycloak;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL
);


ALTER TABLE public.user_attribute OWNER TO keycloak;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO keycloak;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO keycloak;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(36),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO keycloak;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO keycloak;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO keycloak;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO keycloak;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO keycloak;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO keycloak;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO keycloak;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO keycloak;

--
-- Name: user_session; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_session (
    id character varying(36) NOT NULL,
    auth_method character varying(255),
    ip_address character varying(255),
    last_session_refresh integer,
    login_username character varying(255),
    realm_id character varying(255),
    remember_me boolean DEFAULT false NOT NULL,
    started integer,
    user_id character varying(255),
    user_session_state integer,
    broker_session_id character varying(255),
    broker_user_id character varying(255)
);


ALTER TABLE public.user_session OWNER TO keycloak;

--
-- Name: user_session_note; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_session_note (
    user_session character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(2048)
);


ALTER TABLE public.user_session_note OWNER TO keycloak;

--
-- Name: username_login_failure; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.username_login_failure (
    realm_id character varying(36) NOT NULL,
    username character varying(255) NOT NULL,
    failed_login_not_before integer,
    last_failure bigint,
    last_ip_failure character varying(255),
    num_failures integer
);


ALTER TABLE public.username_login_failure OWNER TO keycloak;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO keycloak;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
7e89f0dd-2b57-47de-bedd-34116b5cbc14	\N	auth-cookie	master	61cc22e4-b9c6-47e7-ac02-1ddbea8ee3c3	2	10	f	\N	\N
0f31ed55-e609-4de4-b3e8-32775c5d7be7	\N	auth-spnego	master	61cc22e4-b9c6-47e7-ac02-1ddbea8ee3c3	3	20	f	\N	\N
f198efea-a723-43df-b9bb-b12e877643e0	\N	identity-provider-redirector	master	61cc22e4-b9c6-47e7-ac02-1ddbea8ee3c3	2	25	f	\N	\N
1850e454-50fc-4057-818c-d0b9d698a67a	\N	\N	master	61cc22e4-b9c6-47e7-ac02-1ddbea8ee3c3	2	30	t	cd98212c-6785-48c0-b039-5e4ee2739f03	\N
b3c456b8-0ed6-48d8-af00-621fa084604f	\N	auth-username-password-form	master	cd98212c-6785-48c0-b039-5e4ee2739f03	0	10	f	\N	\N
0cdbdf03-9c73-4c03-acab-e2a6879ae0f6	\N	auth-otp-form	master	cd98212c-6785-48c0-b039-5e4ee2739f03	1	20	f	\N	\N
53402a16-3db8-4f71-986f-f80b2553ac6e	\N	direct-grant-validate-username	master	a731b298-68b4-439b-9c32-a797cd2b193c	0	10	f	\N	\N
c9c10820-fddc-4038-978f-dd06f2b15ead	\N	direct-grant-validate-password	master	a731b298-68b4-439b-9c32-a797cd2b193c	0	20	f	\N	\N
604e5a45-f768-4db4-88af-a0e201fe4a9e	\N	direct-grant-validate-otp	master	a731b298-68b4-439b-9c32-a797cd2b193c	1	30	f	\N	\N
cf36d27f-98ac-4de6-a666-cb84c94c53bf	\N	registration-page-form	master	55ef2c02-8a13-4b07-a0ae-1819eec243fd	0	10	t	a9af1bd0-d2d9-4f86-b588-a048dd64670e	\N
98d40611-c52e-4ebf-97a3-dfbbe4388635	\N	registration-user-creation	master	a9af1bd0-d2d9-4f86-b588-a048dd64670e	0	20	f	\N	\N
10632ab9-3404-432d-a29c-14bf0c18241b	\N	registration-profile-action	master	a9af1bd0-d2d9-4f86-b588-a048dd64670e	0	40	f	\N	\N
296a869e-549e-4442-ba38-537fa6fc9ab9	\N	registration-password-action	master	a9af1bd0-d2d9-4f86-b588-a048dd64670e	0	50	f	\N	\N
b8294aac-ad67-498a-8671-f758050e5a5e	\N	registration-recaptcha-action	master	a9af1bd0-d2d9-4f86-b588-a048dd64670e	3	60	f	\N	\N
3cbcf791-9dac-4275-9fc4-57772fd00f35	\N	reset-credentials-choose-user	master	6c18703e-0471-4e4c-9e82-9e7152f2fb57	0	10	f	\N	\N
a6b8d93d-a046-4c16-8db0-07d3a3b753ad	\N	reset-credential-email	master	6c18703e-0471-4e4c-9e82-9e7152f2fb57	0	20	f	\N	\N
7beb94c6-2b45-4f5f-ba61-ff29007adbfb	\N	reset-password	master	6c18703e-0471-4e4c-9e82-9e7152f2fb57	0	30	f	\N	\N
130f9eb4-20e7-46eb-bd44-9c9578bf88ae	\N	reset-otp	master	6c18703e-0471-4e4c-9e82-9e7152f2fb57	1	40	f	\N	\N
dab95e7c-80e1-44ea-86bd-7fdabdb0e5ec	\N	client-secret	master	c286ae1f-2b78-4f32-b61c-3cea420d921a	2	10	f	\N	\N
b1cb78c1-e8f9-42a0-85bc-c9b0283e1f69	\N	client-jwt	master	c286ae1f-2b78-4f32-b61c-3cea420d921a	2	20	f	\N	\N
28e9fe46-f368-4173-b99c-88e00e030c07	\N	client-secret-jwt	master	c286ae1f-2b78-4f32-b61c-3cea420d921a	2	30	f	\N	\N
cbb406c0-6e56-4a37-a7c8-c703c1fec3ab	\N	client-x509	master	c286ae1f-2b78-4f32-b61c-3cea420d921a	2	40	f	\N	\N
880736eb-078d-4201-b07d-16ed132c4247	\N	idp-review-profile	master	66039a9b-28de-4db1-93cb-a768e9f06a05	0	10	f	\N	a9f23a48-6370-4a41-a4a6-94424c03a517
193235de-7a60-43f3-9b29-b2de22668e82	\N	idp-create-user-if-unique	master	66039a9b-28de-4db1-93cb-a768e9f06a05	2	20	f	\N	48286d6f-f34c-48ec-8d5b-2d9a5118debf
3ea710dc-c9bf-4391-a184-19bcfbb1da7b	\N	\N	master	66039a9b-28de-4db1-93cb-a768e9f06a05	2	30	t	b8b81c29-1760-4fbb-ac4e-25ffe1e1b590	\N
c77a09d4-0a77-425a-b0e4-ba87cd1449bc	\N	idp-confirm-link	master	b8b81c29-1760-4fbb-ac4e-25ffe1e1b590	0	10	f	\N	\N
3f05e0b8-8990-4617-a30d-8d22d420709d	\N	idp-email-verification	master	b8b81c29-1760-4fbb-ac4e-25ffe1e1b590	2	20	f	\N	\N
cbfc46bd-5777-4bd8-8d6e-b3c459fe3417	\N	\N	master	b8b81c29-1760-4fbb-ac4e-25ffe1e1b590	2	30	t	caf2599d-26fd-4b54-8528-5c0082ec2dc0	\N
9f76355d-79ef-4bca-904d-1b308ccf90fc	\N	idp-username-password-form	master	caf2599d-26fd-4b54-8528-5c0082ec2dc0	0	10	f	\N	\N
8c066ba1-a151-41d9-869a-6cccf842aca3	\N	auth-otp-form	master	caf2599d-26fd-4b54-8528-5c0082ec2dc0	1	20	f	\N	\N
e5240631-f99a-4e87-8271-781f656f7d44	\N	http-basic-authenticator	master	e72534cd-9469-424e-b177-48855813bb07	0	10	f	\N	\N
3035e2f1-359d-4cd3-80fe-59ff41de2f29	\N	docker-http-basic-authenticator	master	26906350-dd66-4523-a8c7-432e192eb2d4	0	10	f	\N	\N
32b1285d-e072-4aad-ac5a-9cff3d87a0bc	\N	no-cookie-redirect	master	ecad6f9e-4370-404f-b02f-d7ec6e2925f8	0	10	f	\N	\N
78cd56a9-80b0-49e4-813c-cbfbfa2124ac	\N	basic-auth	master	ecad6f9e-4370-404f-b02f-d7ec6e2925f8	0	20	f	\N	\N
69ffb046-e96f-4429-903f-fe8fc9de833e	\N	basic-auth-otp	master	ecad6f9e-4370-404f-b02f-d7ec6e2925f8	3	30	f	\N	\N
113d5b9c-43bb-454a-bd8e-509f823e8ae3	\N	auth-spnego	master	ecad6f9e-4370-404f-b02f-d7ec6e2925f8	3	40	f	\N	\N
58fcc460-1ac3-4176-b8c7-0852d5a05537	\N	auth-cookie	demo-realm	c3a1c48c-8f50-4c5b-a256-8b2b69cb934e	2	10	f	\N	\N
05401576-b35b-4102-84a5-7eb29b15dbdd	\N	auth-spnego	demo-realm	c3a1c48c-8f50-4c5b-a256-8b2b69cb934e	3	20	f	\N	\N
c0a42202-082a-4413-8524-59bc96553aed	\N	identity-provider-redirector	demo-realm	c3a1c48c-8f50-4c5b-a256-8b2b69cb934e	2	25	f	\N	\N
6e2e9e3f-9eb0-4e5d-93a3-9d8ad31fcbec	\N	\N	demo-realm	c3a1c48c-8f50-4c5b-a256-8b2b69cb934e	2	30	t	be24e0c0-d317-40d2-81d0-ad964d096287	\N
3a7e5d2a-8cfb-42bb-9948-431d54a3125f	\N	auth-username-password-form	demo-realm	be24e0c0-d317-40d2-81d0-ad964d096287	0	10	f	\N	\N
a8a5b0c7-0021-4448-b5b8-18502765bac8	\N	auth-otp-form	demo-realm	be24e0c0-d317-40d2-81d0-ad964d096287	1	20	f	\N	\N
b67efda8-0cdb-494a-a71b-4309ebf33060	\N	direct-grant-validate-username	demo-realm	c0c6fff4-f801-437f-b154-c10f0800ba42	0	10	f	\N	\N
2fba8373-1c48-47bd-92db-59ba6765234e	\N	direct-grant-validate-password	demo-realm	c0c6fff4-f801-437f-b154-c10f0800ba42	0	20	f	\N	\N
c85c52a4-6cea-4bfe-9918-d34299c89eb0	\N	direct-grant-validate-otp	demo-realm	c0c6fff4-f801-437f-b154-c10f0800ba42	1	30	f	\N	\N
a983c8a9-0f87-41e1-8881-947df2a2128e	\N	registration-page-form	demo-realm	8ca230c1-0f87-4262-a1af-6655b83c2062	0	10	t	627e53c6-74d4-4758-8cc4-396ef4b941f1	\N
4349e562-6a3c-4741-877a-09fb76ceadbb	\N	registration-user-creation	demo-realm	627e53c6-74d4-4758-8cc4-396ef4b941f1	0	20	f	\N	\N
2ab09b97-367e-4adc-ad7f-90ac946c29bc	\N	registration-profile-action	demo-realm	627e53c6-74d4-4758-8cc4-396ef4b941f1	0	40	f	\N	\N
362df89e-4b3b-46e0-9d7a-b8d88153f457	\N	registration-password-action	demo-realm	627e53c6-74d4-4758-8cc4-396ef4b941f1	0	50	f	\N	\N
411b35da-d649-4249-9642-450f8a36606d	\N	registration-recaptcha-action	demo-realm	627e53c6-74d4-4758-8cc4-396ef4b941f1	3	60	f	\N	\N
0769e42a-28bf-43c5-9112-ce71b8acecfd	\N	reset-credentials-choose-user	demo-realm	ac20009e-4fc7-4010-a67f-754a2802cb63	0	10	f	\N	\N
a1a5aaf8-6089-437d-8079-4a075832526f	\N	reset-credential-email	demo-realm	ac20009e-4fc7-4010-a67f-754a2802cb63	0	20	f	\N	\N
75757207-1861-42f2-a7f0-1253df803716	\N	reset-password	demo-realm	ac20009e-4fc7-4010-a67f-754a2802cb63	0	30	f	\N	\N
daf8074e-85e4-4644-b78a-6b0dd9df8faf	\N	reset-otp	demo-realm	ac20009e-4fc7-4010-a67f-754a2802cb63	1	40	f	\N	\N
42233979-291e-4f44-bc91-5f8421f37ea1	\N	client-secret	demo-realm	40813a36-c7e7-49df-8961-9e7394d0e2c6	2	10	f	\N	\N
11eb583c-c27d-4484-9ed8-c0ead39c6677	\N	client-jwt	demo-realm	40813a36-c7e7-49df-8961-9e7394d0e2c6	2	20	f	\N	\N
d44104d9-2548-455f-ba4c-8733e0584f24	\N	client-secret-jwt	demo-realm	40813a36-c7e7-49df-8961-9e7394d0e2c6	2	30	f	\N	\N
8dc5aea8-b2c5-4daf-a4ab-8a0492717932	\N	client-x509	demo-realm	40813a36-c7e7-49df-8961-9e7394d0e2c6	2	40	f	\N	\N
5eeb22ff-0424-49a3-a3a2-cf40f5563bfd	\N	idp-review-profile	demo-realm	7e15758d-8c25-4527-beb2-2a99fe0b0e6b	0	10	f	\N	bcf9fd13-3686-4ea4-8701-4c218e410f6f
dd242b04-943d-4dca-9f16-7f75e43563f2	\N	idp-create-user-if-unique	demo-realm	7e15758d-8c25-4527-beb2-2a99fe0b0e6b	2	20	f	\N	11ef512b-a2bc-4b50-9c4b-062a443403fa
00d90f48-e6d3-48b9-8e23-3cdc6edd8bde	\N	\N	demo-realm	7e15758d-8c25-4527-beb2-2a99fe0b0e6b	2	30	t	11d09a13-0d7f-4a37-8f38-63cce32a09d3	\N
319cab2c-ee85-4698-b5f3-3586665552fc	\N	idp-confirm-link	demo-realm	11d09a13-0d7f-4a37-8f38-63cce32a09d3	0	10	f	\N	\N
e85cbe1a-7d7b-4ec2-8083-42727bd80fee	\N	idp-email-verification	demo-realm	11d09a13-0d7f-4a37-8f38-63cce32a09d3	2	20	f	\N	\N
5842657f-31da-40c9-a591-03bfa0e057fa	\N	\N	demo-realm	11d09a13-0d7f-4a37-8f38-63cce32a09d3	2	30	t	73ee68c1-f287-4dde-9625-98e68b70168b	\N
e3141acc-d56b-4678-b7ee-33afa647aa69	\N	idp-username-password-form	demo-realm	73ee68c1-f287-4dde-9625-98e68b70168b	0	10	f	\N	\N
26c59adf-e93c-48ca-a858-f40cab528d76	\N	auth-otp-form	demo-realm	73ee68c1-f287-4dde-9625-98e68b70168b	1	20	f	\N	\N
62faf187-5687-43d1-907a-22c10b6be652	\N	http-basic-authenticator	demo-realm	9402745a-c572-4e0c-bf8a-95e77e3fd542	0	10	f	\N	\N
f9c5307e-00cd-4921-ab59-10a8d44ab79c	\N	docker-http-basic-authenticator	demo-realm	551c47d5-b309-45a4-a32f-3363f22c421d	0	10	f	\N	\N
bce244f0-16a4-4e65-8455-a3584ac9a2f1	\N	no-cookie-redirect	demo-realm	a7bef08a-2e10-4f5b-80ed-6ff69b938e6d	0	10	f	\N	\N
3272c0a4-3209-457b-81bf-dc206c8302d9	\N	basic-auth	demo-realm	a7bef08a-2e10-4f5b-80ed-6ff69b938e6d	0	20	f	\N	\N
c17ff5c2-0870-4671-a7c6-ae0901702f33	\N	basic-auth-otp	demo-realm	a7bef08a-2e10-4f5b-80ed-6ff69b938e6d	3	30	f	\N	\N
53605dec-31d3-4024-9f54-81f851fe501d	\N	auth-spnego	demo-realm	a7bef08a-2e10-4f5b-80ed-6ff69b938e6d	3	40	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
61cc22e4-b9c6-47e7-ac02-1ddbea8ee3c3	browser	browser based authentication	master	basic-flow	t	t
cd98212c-6785-48c0-b039-5e4ee2739f03	forms	Username, password, otp and other auth forms.	master	basic-flow	f	t
a731b298-68b4-439b-9c32-a797cd2b193c	direct grant	OpenID Connect Resource Owner Grant	master	basic-flow	t	t
55ef2c02-8a13-4b07-a0ae-1819eec243fd	registration	registration flow	master	basic-flow	t	t
a9af1bd0-d2d9-4f86-b588-a048dd64670e	registration form	registration form	master	form-flow	f	t
6c18703e-0471-4e4c-9e82-9e7152f2fb57	reset credentials	Reset credentials for a user if they forgot their password or something	master	basic-flow	t	t
c286ae1f-2b78-4f32-b61c-3cea420d921a	clients	Base authentication for clients	master	client-flow	t	t
66039a9b-28de-4db1-93cb-a768e9f06a05	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	master	basic-flow	t	t
b8b81c29-1760-4fbb-ac4e-25ffe1e1b590	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	master	basic-flow	f	t
caf2599d-26fd-4b54-8528-5c0082ec2dc0	Verify Existing Account by Re-authentication	Reauthentication of existing account	master	basic-flow	f	t
e72534cd-9469-424e-b177-48855813bb07	saml ecp	SAML ECP Profile Authentication Flow	master	basic-flow	t	t
26906350-dd66-4523-a8c7-432e192eb2d4	docker auth	Used by Docker clients to authenticate against the IDP	master	basic-flow	t	t
ecad6f9e-4370-404f-b02f-d7ec6e2925f8	http challenge	An authentication flow based on challenge-response HTTP Authentication Schemes	master	basic-flow	t	t
c3a1c48c-8f50-4c5b-a256-8b2b69cb934e	browser	browser based authentication	demo-realm	basic-flow	t	t
be24e0c0-d317-40d2-81d0-ad964d096287	forms	Username, password, otp and other auth forms.	demo-realm	basic-flow	f	t
c0c6fff4-f801-437f-b154-c10f0800ba42	direct grant	OpenID Connect Resource Owner Grant	demo-realm	basic-flow	t	t
8ca230c1-0f87-4262-a1af-6655b83c2062	registration	registration flow	demo-realm	basic-flow	t	t
627e53c6-74d4-4758-8cc4-396ef4b941f1	registration form	registration form	demo-realm	form-flow	f	t
ac20009e-4fc7-4010-a67f-754a2802cb63	reset credentials	Reset credentials for a user if they forgot their password or something	demo-realm	basic-flow	t	t
40813a36-c7e7-49df-8961-9e7394d0e2c6	clients	Base authentication for clients	demo-realm	client-flow	t	t
7e15758d-8c25-4527-beb2-2a99fe0b0e6b	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	demo-realm	basic-flow	t	t
11d09a13-0d7f-4a37-8f38-63cce32a09d3	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	demo-realm	basic-flow	f	t
73ee68c1-f287-4dde-9625-98e68b70168b	Verify Existing Account by Re-authentication	Reauthentication of existing account	demo-realm	basic-flow	f	t
9402745a-c572-4e0c-bf8a-95e77e3fd542	saml ecp	SAML ECP Profile Authentication Flow	demo-realm	basic-flow	t	t
551c47d5-b309-45a4-a32f-3363f22c421d	docker auth	Used by Docker clients to authenticate against the IDP	demo-realm	basic-flow	t	t
a7bef08a-2e10-4f5b-80ed-6ff69b938e6d	http challenge	An authentication flow based on challenge-response HTTP Authentication Schemes	demo-realm	basic-flow	t	t
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
a9f23a48-6370-4a41-a4a6-94424c03a517	review profile config	master
48286d6f-f34c-48ec-8d5b-2d9a5118debf	create unique user config	master
bcf9fd13-3686-4ea4-8701-4c218e410f6f	review profile config	demo-realm
11ef512b-a2bc-4b50-9c4b-062a443403fa	create unique user config	demo-realm
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
a9f23a48-6370-4a41-a4a6-94424c03a517	missing	update.profile.on.first.login
48286d6f-f34c-48ec-8d5b-2d9a5118debf	false	require.password.update.after.registration
bcf9fd13-3686-4ea4-8701-4c218e410f6f	missing	update.profile.on.first.login
11ef512b-a2bc-4b50-9c4b-062a443403fa	false	require.password.update.after.registration
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled) FROM stdin;
e96afb04-c8e3-4d09-b74d-06fa364e582f	t	t	master-realm	0	f	c9d1ff71-4f34-45f5-a24a-7ba23b421d1a	\N	t	\N	f	master	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f
a831efff-56c4-4eb0-b6cb-d4816b326de8	t	f	account	0	f	d9e1d5ed-4f6d-463b-87cc-a8dbfbb4f2b8	/auth/realms/master/account	f	\N	f	master	openid-connect	0	f	f	${client_account}	f	client-secret	\N	\N	\N	t	f	f
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	t	f	broker	0	f	6672202f-fde3-463c-a51c-06b5d8cbbfd2	\N	f	\N	f	master	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f
5705c8e6-4bc0-4531-9edc-773d8295af8f	t	f	security-admin-console	0	t	651453bf-af3b-436c-abaf-0a71f9061c8b	/auth/admin/master/console/index.html	f	\N	f	master	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	\N	\N	\N	t	f	f
022de84b-3e7b-459e-84e1-93f6dacc41ce	t	f	admin-cli	0	t	a8468f30-53a9-4290-a334-2710a630e5ff	\N	f	\N	f	master	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t
ca12f299-0359-4701-ae0f-5c90768b7b34	t	t	demo-realm-realm	0	f	645a7ae6-511e-404f-9575-7e70a4ec9de3	\N	t	\N	f	master	\N	0	f	f	demo-realm Realm	f	client-secret	\N	\N	\N	t	f	f
9656e394-8a00-4a9a-902f-a569910c789a	t	f	realm-management	0	f	70bd5cd0-e366-489d-805e-ecabeb52e602	\N	t	\N	f	demo-realm	openid-connect	0	f	f	${client_realm-management}	f	client-secret	\N	\N	\N	t	f	f
438afdec-0eca-4e17-89f1-8133076985b3	t	f	account	0	f	ed39e42c-a07b-4135-9e83-13767ec94d16	/auth/realms/demo-realm/account	f	\N	f	demo-realm	openid-connect	0	f	f	${client_account}	f	client-secret	\N	\N	\N	t	f	f
38f6fa40-e74a-4c21-930c-b86be2c436af	t	f	broker	0	f	60a291a8-7833-49f0-a472-ec8d1eff8a3c	\N	f	\N	f	demo-realm	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f
864375cb-3edf-44ed-85b0-8fd316506d30	t	f	security-admin-console	0	t	b65f498b-83dd-4d26-b05c-25ac4c4bd8ad	/auth/admin/demo-realm/console/index.html	f	\N	f	demo-realm	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	\N	\N	\N	t	f	f
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	t	f	admin-cli	0	t	0e765172-8250-4a00-a4ee-c2e2057fb6f5	\N	f	\N	f	demo-realm	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	t	t	demo-client	0	f	61e01c5e-0b5e-42d5-b988-86901cbfff43	\N	f	\N	f	demo-realm	openid-connect	-1	f	f	\N	f	client-secret	\N	\N	\N	t	f	t
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_attributes (client_id, value, name) FROM stdin;
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.server.signature
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.server.signature.keyinfo.ext
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.assertion.signature
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.client.signature
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.encrypt
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.authnstatement
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.onetimeuse.condition
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml_force_name_id_format
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.multivalued.roles
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	saml.force.post.binding
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	exclude.session.state.from.auth.response
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	tls.client.certificate.bound.access.tokens
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	false	display.on.consent.screen
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_default_roles; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_default_roles (client_id, role_id) FROM stdin;
a831efff-56c4-4eb0-b6cb-d4816b326de8	d7e91971-22d9-4051-b421-6775f9ddcc3a
a831efff-56c4-4eb0-b6cb-d4816b326de8	ab5d210f-5caf-4449-aed3-502dd36e7ebe
438afdec-0eca-4e17-89f1-8133076985b3	b5fe97e3-364e-4d57-8039-a29c8e950ab8
438afdec-0eca-4e17-89f1-8133076985b3	1cbf3fee-dada-4fb5-b2c0-583fbc1ee8bf
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
a22c9db1-3865-4562-aaf9-52a915fd2921	offline_access	master	OpenID Connect built-in scope: offline_access	openid-connect
8a83729e-8538-4988-b438-eee87d810358	role_list	master	SAML role list	saml
5409d19b-5095-4145-9edb-0175256d59b4	profile	master	OpenID Connect built-in scope: profile	openid-connect
159ff0c7-f724-408b-8298-ab27e1304ba4	email	master	OpenID Connect built-in scope: email	openid-connect
0617a61c-2ce7-4f90-9c5a-5362af0b4c63	address	master	OpenID Connect built-in scope: address	openid-connect
e100bf70-1e86-4077-a735-37c1c58f657d	phone	master	OpenID Connect built-in scope: phone	openid-connect
87f7a2d0-5faf-4b8e-a913-a6deb70130d9	roles	master	OpenID Connect scope for add user roles to the access token	openid-connect
57e73925-0ec4-4b99-b969-518226e19c21	web-origins	master	OpenID Connect scope for add allowed web origins to the access token	openid-connect
1ee08abf-5282-4783-8eca-e889e7563ca9	microprofile-jwt	master	Microprofile - JWT built-in scope	openid-connect
b056306b-82ba-4751-99df-6eeb87a74dce	offline_access	demo-realm	OpenID Connect built-in scope: offline_access	openid-connect
1ac840b4-2517-410d-8219-eae3b717a2a4	role_list	demo-realm	SAML role list	saml
69ebabb2-0ced-49ad-b8cc-99ef083ea52b	profile	demo-realm	OpenID Connect built-in scope: profile	openid-connect
67754b0a-38a9-458e-9c59-3f1fdcd2439b	email	demo-realm	OpenID Connect built-in scope: email	openid-connect
7031920c-9eb7-4389-86fb-f2cd3141f51d	address	demo-realm	OpenID Connect built-in scope: address	openid-connect
f4566753-b0d7-477b-9028-4fd25f418306	phone	demo-realm	OpenID Connect built-in scope: phone	openid-connect
ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	roles	demo-realm	OpenID Connect scope for add user roles to the access token	openid-connect
ac7bf87c-385e-41ec-8596-44c38dc6850b	web-origins	demo-realm	OpenID Connect scope for add allowed web origins to the access token	openid-connect
b058e660-4520-4503-8f2a-0e3cbac25da8	microprofile-jwt	demo-realm	Microprofile - JWT built-in scope	openid-connect
0e947f5d-fbe9-4310-ba4f-c050ecdd3a52	demo-scopes	demo-realm	\N	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
a22c9db1-3865-4562-aaf9-52a915fd2921	true	display.on.consent.screen
a22c9db1-3865-4562-aaf9-52a915fd2921	${offlineAccessScopeConsentText}	consent.screen.text
8a83729e-8538-4988-b438-eee87d810358	true	display.on.consent.screen
8a83729e-8538-4988-b438-eee87d810358	${samlRoleListScopeConsentText}	consent.screen.text
5409d19b-5095-4145-9edb-0175256d59b4	true	display.on.consent.screen
5409d19b-5095-4145-9edb-0175256d59b4	${profileScopeConsentText}	consent.screen.text
5409d19b-5095-4145-9edb-0175256d59b4	true	include.in.token.scope
159ff0c7-f724-408b-8298-ab27e1304ba4	true	display.on.consent.screen
159ff0c7-f724-408b-8298-ab27e1304ba4	${emailScopeConsentText}	consent.screen.text
159ff0c7-f724-408b-8298-ab27e1304ba4	true	include.in.token.scope
0617a61c-2ce7-4f90-9c5a-5362af0b4c63	true	display.on.consent.screen
0617a61c-2ce7-4f90-9c5a-5362af0b4c63	${addressScopeConsentText}	consent.screen.text
0617a61c-2ce7-4f90-9c5a-5362af0b4c63	true	include.in.token.scope
e100bf70-1e86-4077-a735-37c1c58f657d	true	display.on.consent.screen
e100bf70-1e86-4077-a735-37c1c58f657d	${phoneScopeConsentText}	consent.screen.text
e100bf70-1e86-4077-a735-37c1c58f657d	true	include.in.token.scope
87f7a2d0-5faf-4b8e-a913-a6deb70130d9	true	display.on.consent.screen
87f7a2d0-5faf-4b8e-a913-a6deb70130d9	${rolesScopeConsentText}	consent.screen.text
87f7a2d0-5faf-4b8e-a913-a6deb70130d9	false	include.in.token.scope
57e73925-0ec4-4b99-b969-518226e19c21	false	display.on.consent.screen
57e73925-0ec4-4b99-b969-518226e19c21		consent.screen.text
57e73925-0ec4-4b99-b969-518226e19c21	false	include.in.token.scope
1ee08abf-5282-4783-8eca-e889e7563ca9	false	display.on.consent.screen
1ee08abf-5282-4783-8eca-e889e7563ca9	true	include.in.token.scope
b056306b-82ba-4751-99df-6eeb87a74dce	true	display.on.consent.screen
b056306b-82ba-4751-99df-6eeb87a74dce	${offlineAccessScopeConsentText}	consent.screen.text
1ac840b4-2517-410d-8219-eae3b717a2a4	true	display.on.consent.screen
1ac840b4-2517-410d-8219-eae3b717a2a4	${samlRoleListScopeConsentText}	consent.screen.text
69ebabb2-0ced-49ad-b8cc-99ef083ea52b	true	display.on.consent.screen
69ebabb2-0ced-49ad-b8cc-99ef083ea52b	${profileScopeConsentText}	consent.screen.text
69ebabb2-0ced-49ad-b8cc-99ef083ea52b	true	include.in.token.scope
67754b0a-38a9-458e-9c59-3f1fdcd2439b	true	display.on.consent.screen
67754b0a-38a9-458e-9c59-3f1fdcd2439b	${emailScopeConsentText}	consent.screen.text
67754b0a-38a9-458e-9c59-3f1fdcd2439b	true	include.in.token.scope
7031920c-9eb7-4389-86fb-f2cd3141f51d	true	display.on.consent.screen
7031920c-9eb7-4389-86fb-f2cd3141f51d	${addressScopeConsentText}	consent.screen.text
7031920c-9eb7-4389-86fb-f2cd3141f51d	true	include.in.token.scope
f4566753-b0d7-477b-9028-4fd25f418306	true	display.on.consent.screen
f4566753-b0d7-477b-9028-4fd25f418306	${phoneScopeConsentText}	consent.screen.text
f4566753-b0d7-477b-9028-4fd25f418306	true	include.in.token.scope
ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	true	display.on.consent.screen
ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	${rolesScopeConsentText}	consent.screen.text
ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	false	include.in.token.scope
ac7bf87c-385e-41ec-8596-44c38dc6850b	false	display.on.consent.screen
ac7bf87c-385e-41ec-8596-44c38dc6850b		consent.screen.text
ac7bf87c-385e-41ec-8596-44c38dc6850b	false	include.in.token.scope
b058e660-4520-4503-8f2a-0e3cbac25da8	false	display.on.consent.screen
b058e660-4520-4503-8f2a-0e3cbac25da8	true	include.in.token.scope
0e947f5d-fbe9-4310-ba4f-c050ecdd3a52	true	display.on.consent.screen
0e947f5d-fbe9-4310-ba4f-c050ecdd3a52	true	include.in.token.scope
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
a831efff-56c4-4eb0-b6cb-d4816b326de8	8a83729e-8538-4988-b438-eee87d810358	t
022de84b-3e7b-459e-84e1-93f6dacc41ce	8a83729e-8538-4988-b438-eee87d810358	t
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	8a83729e-8538-4988-b438-eee87d810358	t
e96afb04-c8e3-4d09-b74d-06fa364e582f	8a83729e-8538-4988-b438-eee87d810358	t
5705c8e6-4bc0-4531-9edc-773d8295af8f	8a83729e-8538-4988-b438-eee87d810358	t
a831efff-56c4-4eb0-b6cb-d4816b326de8	5409d19b-5095-4145-9edb-0175256d59b4	t
a831efff-56c4-4eb0-b6cb-d4816b326de8	159ff0c7-f724-408b-8298-ab27e1304ba4	t
a831efff-56c4-4eb0-b6cb-d4816b326de8	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
a831efff-56c4-4eb0-b6cb-d4816b326de8	57e73925-0ec4-4b99-b969-518226e19c21	t
a831efff-56c4-4eb0-b6cb-d4816b326de8	a22c9db1-3865-4562-aaf9-52a915fd2921	f
a831efff-56c4-4eb0-b6cb-d4816b326de8	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
a831efff-56c4-4eb0-b6cb-d4816b326de8	e100bf70-1e86-4077-a735-37c1c58f657d	f
a831efff-56c4-4eb0-b6cb-d4816b326de8	1ee08abf-5282-4783-8eca-e889e7563ca9	f
022de84b-3e7b-459e-84e1-93f6dacc41ce	5409d19b-5095-4145-9edb-0175256d59b4	t
022de84b-3e7b-459e-84e1-93f6dacc41ce	159ff0c7-f724-408b-8298-ab27e1304ba4	t
022de84b-3e7b-459e-84e1-93f6dacc41ce	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
022de84b-3e7b-459e-84e1-93f6dacc41ce	57e73925-0ec4-4b99-b969-518226e19c21	t
022de84b-3e7b-459e-84e1-93f6dacc41ce	a22c9db1-3865-4562-aaf9-52a915fd2921	f
022de84b-3e7b-459e-84e1-93f6dacc41ce	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
022de84b-3e7b-459e-84e1-93f6dacc41ce	e100bf70-1e86-4077-a735-37c1c58f657d	f
022de84b-3e7b-459e-84e1-93f6dacc41ce	1ee08abf-5282-4783-8eca-e889e7563ca9	f
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	5409d19b-5095-4145-9edb-0175256d59b4	t
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	159ff0c7-f724-408b-8298-ab27e1304ba4	t
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	57e73925-0ec4-4b99-b969-518226e19c21	t
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	a22c9db1-3865-4562-aaf9-52a915fd2921	f
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	e100bf70-1e86-4077-a735-37c1c58f657d	f
46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	1ee08abf-5282-4783-8eca-e889e7563ca9	f
e96afb04-c8e3-4d09-b74d-06fa364e582f	5409d19b-5095-4145-9edb-0175256d59b4	t
e96afb04-c8e3-4d09-b74d-06fa364e582f	159ff0c7-f724-408b-8298-ab27e1304ba4	t
e96afb04-c8e3-4d09-b74d-06fa364e582f	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
e96afb04-c8e3-4d09-b74d-06fa364e582f	57e73925-0ec4-4b99-b969-518226e19c21	t
e96afb04-c8e3-4d09-b74d-06fa364e582f	a22c9db1-3865-4562-aaf9-52a915fd2921	f
e96afb04-c8e3-4d09-b74d-06fa364e582f	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
e96afb04-c8e3-4d09-b74d-06fa364e582f	e100bf70-1e86-4077-a735-37c1c58f657d	f
e96afb04-c8e3-4d09-b74d-06fa364e582f	1ee08abf-5282-4783-8eca-e889e7563ca9	f
5705c8e6-4bc0-4531-9edc-773d8295af8f	5409d19b-5095-4145-9edb-0175256d59b4	t
5705c8e6-4bc0-4531-9edc-773d8295af8f	159ff0c7-f724-408b-8298-ab27e1304ba4	t
5705c8e6-4bc0-4531-9edc-773d8295af8f	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
5705c8e6-4bc0-4531-9edc-773d8295af8f	57e73925-0ec4-4b99-b969-518226e19c21	t
5705c8e6-4bc0-4531-9edc-773d8295af8f	a22c9db1-3865-4562-aaf9-52a915fd2921	f
5705c8e6-4bc0-4531-9edc-773d8295af8f	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
5705c8e6-4bc0-4531-9edc-773d8295af8f	e100bf70-1e86-4077-a735-37c1c58f657d	f
5705c8e6-4bc0-4531-9edc-773d8295af8f	1ee08abf-5282-4783-8eca-e889e7563ca9	f
ca12f299-0359-4701-ae0f-5c90768b7b34	8a83729e-8538-4988-b438-eee87d810358	t
ca12f299-0359-4701-ae0f-5c90768b7b34	5409d19b-5095-4145-9edb-0175256d59b4	t
ca12f299-0359-4701-ae0f-5c90768b7b34	159ff0c7-f724-408b-8298-ab27e1304ba4	t
ca12f299-0359-4701-ae0f-5c90768b7b34	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
ca12f299-0359-4701-ae0f-5c90768b7b34	57e73925-0ec4-4b99-b969-518226e19c21	t
ca12f299-0359-4701-ae0f-5c90768b7b34	a22c9db1-3865-4562-aaf9-52a915fd2921	f
ca12f299-0359-4701-ae0f-5c90768b7b34	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
ca12f299-0359-4701-ae0f-5c90768b7b34	e100bf70-1e86-4077-a735-37c1c58f657d	f
ca12f299-0359-4701-ae0f-5c90768b7b34	1ee08abf-5282-4783-8eca-e889e7563ca9	f
438afdec-0eca-4e17-89f1-8133076985b3	1ac840b4-2517-410d-8219-eae3b717a2a4	t
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	1ac840b4-2517-410d-8219-eae3b717a2a4	t
38f6fa40-e74a-4c21-930c-b86be2c436af	1ac840b4-2517-410d-8219-eae3b717a2a4	t
9656e394-8a00-4a9a-902f-a569910c789a	1ac840b4-2517-410d-8219-eae3b717a2a4	t
864375cb-3edf-44ed-85b0-8fd316506d30	1ac840b4-2517-410d-8219-eae3b717a2a4	t
438afdec-0eca-4e17-89f1-8133076985b3	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
438afdec-0eca-4e17-89f1-8133076985b3	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
438afdec-0eca-4e17-89f1-8133076985b3	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
438afdec-0eca-4e17-89f1-8133076985b3	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
438afdec-0eca-4e17-89f1-8133076985b3	b056306b-82ba-4751-99df-6eeb87a74dce	f
438afdec-0eca-4e17-89f1-8133076985b3	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
438afdec-0eca-4e17-89f1-8133076985b3	f4566753-b0d7-477b-9028-4fd25f418306	f
438afdec-0eca-4e17-89f1-8133076985b3	b058e660-4520-4503-8f2a-0e3cbac25da8	f
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	b056306b-82ba-4751-99df-6eeb87a74dce	f
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	f4566753-b0d7-477b-9028-4fd25f418306	f
bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	b058e660-4520-4503-8f2a-0e3cbac25da8	f
38f6fa40-e74a-4c21-930c-b86be2c436af	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
38f6fa40-e74a-4c21-930c-b86be2c436af	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
38f6fa40-e74a-4c21-930c-b86be2c436af	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
38f6fa40-e74a-4c21-930c-b86be2c436af	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
38f6fa40-e74a-4c21-930c-b86be2c436af	b056306b-82ba-4751-99df-6eeb87a74dce	f
38f6fa40-e74a-4c21-930c-b86be2c436af	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
38f6fa40-e74a-4c21-930c-b86be2c436af	f4566753-b0d7-477b-9028-4fd25f418306	f
38f6fa40-e74a-4c21-930c-b86be2c436af	b058e660-4520-4503-8f2a-0e3cbac25da8	f
9656e394-8a00-4a9a-902f-a569910c789a	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
9656e394-8a00-4a9a-902f-a569910c789a	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
9656e394-8a00-4a9a-902f-a569910c789a	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
9656e394-8a00-4a9a-902f-a569910c789a	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
9656e394-8a00-4a9a-902f-a569910c789a	b056306b-82ba-4751-99df-6eeb87a74dce	f
9656e394-8a00-4a9a-902f-a569910c789a	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
9656e394-8a00-4a9a-902f-a569910c789a	f4566753-b0d7-477b-9028-4fd25f418306	f
9656e394-8a00-4a9a-902f-a569910c789a	b058e660-4520-4503-8f2a-0e3cbac25da8	f
864375cb-3edf-44ed-85b0-8fd316506d30	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
864375cb-3edf-44ed-85b0-8fd316506d30	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
864375cb-3edf-44ed-85b0-8fd316506d30	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
864375cb-3edf-44ed-85b0-8fd316506d30	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
864375cb-3edf-44ed-85b0-8fd316506d30	b056306b-82ba-4751-99df-6eeb87a74dce	f
864375cb-3edf-44ed-85b0-8fd316506d30	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
864375cb-3edf-44ed-85b0-8fd316506d30	f4566753-b0d7-477b-9028-4fd25f418306	f
864375cb-3edf-44ed-85b0-8fd316506d30	b058e660-4520-4503-8f2a-0e3cbac25da8	f
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	1ac840b4-2517-410d-8219-eae3b717a2a4	t
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	b056306b-82ba-4751-99df-6eeb87a74dce	f
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	f4566753-b0d7-477b-9028-4fd25f418306	f
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	b058e660-4520-4503-8f2a-0e3cbac25da8	f
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	0e947f5d-fbe9-4310-ba4f-c050ecdd3a52	t
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
a22c9db1-3865-4562-aaf9-52a915fd2921	34c8ae53-e5dd-4a42-bda1-9fe88860caa2
b056306b-82ba-4751-99df-6eeb87a74dce	3169f3f9-83ae-4cfd-8fa9-34b8b37d68a9
\.


--
-- Data for Name: client_session; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_session (id, client_id, redirect_uri, state, "timestamp", session_id, auth_method, realm_id, auth_user_id, current_action) FROM stdin;
\.


--
-- Data for Name: client_session_auth_status; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_session_auth_status (authenticator, status, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_note; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_prot_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_session_prot_mapper (protocol_mapper_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_role; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_session_role (role_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_user_session_note; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_user_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
4dcb3fa2-86ef-40fa-a33f-d3d7a9d99f74	Trusted Hosts	master	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
a4aaa01d-0973-4f1a-9a5e-d4ba5b4f406d	Consent Required	master	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
83173471-cd1e-4b22-93c6-7c83b4a7cd44	Full Scope Disabled	master	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
67e61cd1-c241-4611-871f-23b69d3f16cb	Max Clients Limit	master	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
dcc2e4e1-006b-4772-bf79-b67494097bd0	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
4655e118-aa2d-4d18-891b-8eac36dca82c	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
9282c982-a839-48a3-867c-d0506ba4d038	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
c3baf0d8-eeeb-46de-8a82-06ef4a8b4353	rsa-generated	master	rsa-generated	org.keycloak.keys.KeyProvider	master	\N
83a312db-a26b-41e2-9d87-8f6d0721f329	hmac-generated	master	hmac-generated	org.keycloak.keys.KeyProvider	master	\N
036d8d4e-49b9-439b-943e-cee839f3b123	aes-generated	master	aes-generated	org.keycloak.keys.KeyProvider	master	\N
dc157aaa-ce4a-4ba7-a35c-08f7e614849f	rsa-generated	demo-realm	rsa-generated	org.keycloak.keys.KeyProvider	demo-realm	\N
d8293968-b1c5-4791-bcd5-2d1677267f86	hmac-generated	demo-realm	hmac-generated	org.keycloak.keys.KeyProvider	demo-realm	\N
db18a9b9-ae7b-4461-a65e-97800c733e87	aes-generated	demo-realm	aes-generated	org.keycloak.keys.KeyProvider	demo-realm	\N
c528b20c-b427-4082-92d9-583e5e63c494	Trusted Hosts	demo-realm	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	anonymous
22d88f2c-263a-4f22-93a2-d6f85084fcc0	Consent Required	demo-realm	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	anonymous
47a670a5-41d7-4723-80d9-c89c529b89d6	Full Scope Disabled	demo-realm	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	anonymous
68afb40c-9a0c-4555-b35c-c9d955ced156	Max Clients Limit	demo-realm	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	anonymous
ef599fb9-3d6e-45d3-ae29-969be85ec6cc	Allowed Protocol Mapper Types	demo-realm	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	anonymous
c51ab623-c02b-4a5a-ada5-e61df41de012	Allowed Client Scopes	demo-realm	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	anonymous
fa445be6-69b7-40a2-b065-d9c48f59df4b	Allowed Protocol Mapper Types	demo-realm	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	authenticated
53faefab-0ef6-4773-9e47-13a39c9c4d3d	Allowed Client Scopes	demo-realm	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	demo-realm	authenticated
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
6344b1ea-474f-4c4c-a162-806d483466af	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	saml-user-property-mapper
d551b855-ec91-4e20-b8ef-b9fba00231eb	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	oidc-full-name-mapper
51e047dd-901c-4a8d-9c71-26c1adc78dde	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
4c388ccb-b2a5-46d1-ac6e-704afd9130ab	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	saml-role-list-mapper
01607400-335f-4591-8ae1-20178ce7ed51	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	oidc-address-mapper
7ab622da-67d4-4143-9abd-6321daafc034	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	saml-user-attribute-mapper
a0105998-c0d9-404e-b711-571906bb350c	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
cd346d7e-4c63-4a5f-ac0f-1b382d56e9a7	09d0dbdd-af5c-4425-a59b-9bf6ca2e7ab5	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
bf584713-26bf-4900-acf6-8f67a5c6f785	4dcb3fa2-86ef-40fa-a33f-d3d7a9d99f74	client-uris-must-match	true
5a22e6d7-58cb-4315-82ba-555139e914df	4dcb3fa2-86ef-40fa-a33f-d3d7a9d99f74	host-sending-registration-request-must-match	true
fb8c639b-9d60-4431-ba1b-38d8b60bb529	67e61cd1-c241-4611-871f-23b69d3f16cb	max-clients	200
f66dc5fe-5d32-4d3b-94ec-ac6e27ad03ee	dcc2e4e1-006b-4772-bf79-b67494097bd0	allow-default-scopes	true
428a7451-ad32-446e-918c-f02b68c218b4	9282c982-a839-48a3-867c-d0506ba4d038	allow-default-scopes	true
7a14dd96-e884-40de-886f-e30d35b14973	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
183b0178-3ead-4a81-9f5a-9a3e8c606351	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	oidc-address-mapper
ab8ac95a-b12c-4543-84bd-c75a84d855a9	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	saml-user-property-mapper
df9e8b8b-ff0d-4f06-9781-c8f3b64b6cc8	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	oidc-full-name-mapper
9d068b72-a56f-400b-b246-6752973d6272	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
97df664e-3acd-4c48-984a-e960379d9d09	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	saml-user-attribute-mapper
6f893e21-56a4-4847-ad3d-043006d79251	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
b46c1095-c6cb-435e-85f1-5920f472d612	4655e118-aa2d-4d18-891b-8eac36dca82c	allowed-protocol-mapper-types	saml-role-list-mapper
a65fc249-f0fb-4cab-a997-c7fc6b91427d	83a312db-a26b-41e2-9d87-8f6d0721f329	algorithm	HS256
57abccf9-2fde-4709-838e-93802463002d	83a312db-a26b-41e2-9d87-8f6d0721f329	priority	100
6446e164-ad6c-49a2-bb60-975f06571d63	83a312db-a26b-41e2-9d87-8f6d0721f329	secret	RtKvvVGeTMEHT0MJVOB16KIgBR__BDzxm5Nq8zEhfBcvir2x3TgTAMMoEbttQEGYqJ_3FnV9yW2q2337KjMAhw
ed87f8f0-b831-4e6d-af58-1fe6817237b0	83a312db-a26b-41e2-9d87-8f6d0721f329	kid	8cdd186f-c579-426a-8dd9-9d0b0e4d9319
5769a6ce-b110-4795-be37-94f09d3f0234	036d8d4e-49b9-439b-943e-cee839f3b123	secret	NEMLlaiA4gMR84aBopFJsA
a98c65a0-5984-4431-9d59-1811320dde26	036d8d4e-49b9-439b-943e-cee839f3b123	kid	bb46c78d-406d-41bc-a030-00685525d5c1
9d62df0f-7057-4a8a-bffc-9a25f87f3981	036d8d4e-49b9-439b-943e-cee839f3b123	priority	100
254cd800-5e20-4b62-ba00-c4cb80214d95	c3baf0d8-eeeb-46de-8a82-06ef4a8b4353	privateKey	MIIEogIBAAKCAQEAlBa1ZvQei3vxoSRlZLqcRRZAKo1Y75sG7HZdLG+vHQzIpq0a0LuetZ4PZBgYpu6ZXenoacf65psuXLAVoLpTktJV1ZVmItM7VYffMbgpgie71ksczJsJ0xOv9c876LTSv/qMIQH/JGvstfwltX1s2oIX81APeXwTR43Kj0EB6JR6ePZgDadnqsqOohlFAff1iEAkwlHfQAoWEI0RqkXukNE6syDdr02tnK2w5JyDDglSoYGa77O61lstgbJnmhIy/bDP1MI4HwqII+HlLHbBu0SqzKudgm0cXdtz4kIoVxfOdkPdyrrUmYwO7ed/HPfJPZx0hGe8U5LZVBFDPGMOCwIDAQABAoIBAFq3ioq2ExwZYkz3sdFB68b6uXYXvpqRWm1ymONGy3w9P5GzS1EBDlltqToE9N0WHweD6ecbJZ0tBPqst6MNYXL4vLIpYjcFNTzRDi40BeGAm7XLr6m7dApE7i7js2x7kPsf7cWupnDWWFynSSZj3lIBDdD0g3ZFRr43oxWcmiGyHL/UzEY3VT9D9qYVDRQzexgXGGSJEXJgdA/Ku58PRQCxA0KF4/f+TGb5zhr4WjMBhcheothbgDyZ4lDGslgkKNP7PqpP0LhXIoq+d45Z9Rv/FtfpogTwVZJnlvqvrKKTE+HqMapO8xJmaDU07DpqEW4/s6kCcxlXr9TK4BN0OzkCgYEAxLn9cM5zljgXCFm6ZXjteK5+OEnYm50PVNedr6o518mDzsxKHZ1a+HbFkvle038e25T035UEuE9PnpivDSTvyfwdtlheGyEGe3pTx9FDZtzx7E5hAS2xOvBNsMbb3NONXPZIXvC+pZp/caHVoVihCg4L8gNRYXcah2e+nCIvp2cCgYEAwLUpaJYi+ydCPtH6kzzzxB/NieqwE8i3d2l+c4FTkEI8dCmOUNNFZxwi8K9bD8C7PDNMJgwGx45vUFONfPZSB9ON8XNE/tLfdiNL5gPjruYtibICPLENNDxWoL3wwpNTGsdXkcYhhBU8ln1Lycl5+nQ2uNC3mTTLDgqh7vUwcb0CgYBzLwL5XafHuKejuAWvDBLeqiw1AOfWlSs43dXx2JVthwuptWtf05ZEDCa6W0/uPWvv3VNS5YmR8L4JehRkec/8T6WF8k+HStrkyUbso9X3ED6FwY6ChiJTBAg5DPYGYcdPOtQ84nB9vewIuFzAz4fav0a3OMIZcwcRaOjtugZ02QKBgEKlJIn4CmcDf8SMB/WtybwVJ5c/498jtleE02eM3WJxlciyqnZHaqQrNeY5Luv2wooiT36FAD85gkOsca063sm4H0nWjJD4SrHnqRMGW1KcZjlNp7pnnOJoz6jNp5sTKlWDhURz2hl84rRE5tYFaLr2QAqQnD5O5L6ZbMFgaH2dAoGABaY8c+ed4UjjaR/hCZJScSezffsIK52kDXJviAwPekZ2u8mA/V1eF2X2VSqJh9fRmbm1JlrmMU//IVRyo6pRtWQTZrigXJCFAprd+dG4oSQnTSPTiXa1GdcCU6KQ4FyqE+vQd+u+7e9qA3Sewvm5Y1RwaW21lb8syWFQiztJY1g=
3254a0fe-8dfe-4ac2-a10a-872d67ffe359	c3baf0d8-eeeb-46de-8a82-06ef4a8b4353	priority	100
6d60788c-0355-416c-9ecb-7466061f754f	c3baf0d8-eeeb-46de-8a82-06ef4a8b4353	certificate	MIICmzCCAYMCBgGKRjzJOzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjMwODMwMTEzNjQzWhcNMzMwODMwMTEzODIzWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUFrVm9B6Le/GhJGVkupxFFkAqjVjvmwbsdl0sb68dDMimrRrQu561ng9kGBim7pld6ehpx/rmmy5csBWgulOS0lXVlWYi0ztVh98xuCmCJ7vWSxzMmwnTE6/1zzvotNK/+owhAf8ka+y1/CW1fWzaghfzUA95fBNHjcqPQQHolHp49mANp2eqyo6iGUUB9/WIQCTCUd9AChYQjRGqRe6Q0TqzIN2vTa2crbDknIMOCVKhgZrvs7rWWy2BsmeaEjL9sM/UwjgfCogj4eUsdsG7RKrMq52CbRxd23PiQihXF852Q93KutSZjA7t538c98k9nHSEZ7xTktlUEUM8Yw4LAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAMt4dGnczNKA9rkazkvQlGWlajcvR79qImeWQ13CwEXic9MqemuNkZ8j1q3iIvsQZKWBrW/LiJKC7Iy3R8xHRMhX34uEbUyiF0rS7xlQ8ZT1Ejb0PdgY45yjkvbHg9839yBsTNJ2k1GGhKTxf2rt8le0mLYmS/z7rRSimwPZozQZ544d7a4VcmuCKgFR4YQbw47h1snaUcWvtSGvQy7v2ZIiiQs8GE7zHfPo/TAWkskmoyxxbcyRdHR90MEXbXshBKiBGCGiEWteHTPzmk1mAGULVmeGdFjyQTHE7ctw4TM9Qzpx/kHsQCm25wWxOA+vi4bFx+FD+IVkZsbFbX+aR4=
0de3e4ff-930e-47ea-87bd-45ec7196ed8c	db18a9b9-ae7b-4461-a65e-97800c733e87	kid	f08c04d1-2fd2-4c4b-9c2c-36e93fd4c587
24f56714-ae38-4373-ab3f-9375429a2287	db18a9b9-ae7b-4461-a65e-97800c733e87	priority	100
cb0e34d0-31a3-406e-b628-2e60f332eea5	db18a9b9-ae7b-4461-a65e-97800c733e87	secret	3Ykf7xiLxeaziWgH8BvXtA
f4829285-834e-4797-af9b-27fedc1a9203	d8293968-b1c5-4791-bcd5-2d1677267f86	priority	100
47e40d8b-a44d-4faf-9626-14ce0e5c61ff	d8293968-b1c5-4791-bcd5-2d1677267f86	algorithm	HS256
761509cf-0455-4284-9bdb-8acbdbd7d891	d8293968-b1c5-4791-bcd5-2d1677267f86	kid	8541a397-76de-458e-9ecc-7273d35325fa
860c6f47-8464-47fa-a0bc-3c5d34daa018	d8293968-b1c5-4791-bcd5-2d1677267f86	secret	Ixy_ABmJP2EN4qxRUrOR2zs22lEE9yRJML_4sBNsIvTq-QNrDzn9r6wIw3fBv2-o236zMorXBYNMXg0v6JG4yg
e67d177e-78ef-4ee6-a904-e8bd5031df5a	dc157aaa-ce4a-4ba7-a35c-08f7e614849f	priority	100
84b17ff3-7856-452b-b11c-c923f3c4a01e	dc157aaa-ce4a-4ba7-a35c-08f7e614849f	certificate	MIICozCCAYsCBgGKRkV1ETANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApkZW1vLXJlYWxtMB4XDTIzMDgzMDExNDYxMVoXDTMzMDgzMDExNDc1MVowFTETMBEGA1UEAwwKZGVtby1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJXCKR3+rukm70qBIUCPLHt7T3JHh6f/Fg8TJSoh6mlsfw12NDfzesdp+Bc8CzGF7ml6Oh3Sw9AcwWUHiUD/wdA7C0jCh3M+hbzTCHppffuCZ2tkg0N7JpCyL8/tcgVZbO6X1MTXB2+2N5mMQyswagnLzM7Fpps513g5AFHf+9/oOYuCEbQaKEF/CCJkA+IjZbUL+RTh+GkeXMESmovVxZMY5R2GNIgNz92XrAO6W2JGi7mn3YrZEg0BrROlzan545VAAKpTc6iAJieaTEYn02JSTOsdI33kxMfOcvTIsc+muijKxENNVkjalgkk6Pl9hBjmYWjMKDlQY8YaofVpnVkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi/dqnY2CDD45AIdYmaxAMcmZ/NjcZSigy9gtyUEtOlnUMNKPru9WAYY17b64OPEPK2lGFUJK5BixVfPySoxDHknXiZXyk4lzt7rUIHgjCtKkRuOvTpjiZbQ6aNah/21To9GtlK5oTcXa67mSfSQnfof8ua3BzEZ8QwaT8lkZTmhGf+9JWKWEYmP4YbTd9TrxvGeYJBogxnF3jAXvcT2GQqx2jNnneNwn5fIiBSc1FB3DFvovGXkVuXVAmR6Edc4JC9vKxLJLLyu3QQzjjQEHrz96gDP09XYuNKF4xLyl5y31ai3LWB8EFdzYuZhC77X7oZtEiqMsJ596MNzj7xOBkA==
563e3a37-748e-4aa8-9af1-d761b1ac681a	dc157aaa-ce4a-4ba7-a35c-08f7e614849f	privateKey	MIIEowIBAAKCAQEAlcIpHf6u6SbvSoEhQI8se3tPckeHp/8WDxMlKiHqaWx/DXY0N/N6x2n4FzwLMYXuaXo6HdLD0BzBZQeJQP/B0DsLSMKHcz6FvNMIeml9+4Jna2SDQ3smkLIvz+1yBVls7pfUxNcHb7Y3mYxDKzBqCcvMzsWmmznXeDkAUd/73+g5i4IRtBooQX8IImQD4iNltQv5FOH4aR5cwRKai9XFkxjlHYY0iA3P3ZesA7pbYkaLuafditkSDQGtE6XNqfnjlUAAqlNzqIAmJ5pMRifTYlJM6x0jfeTEx85y9Mixz6a6KMrEQ01WSNqWCSTo+X2EGOZhaMwoOVBjxhqh9WmdWQIDAQABAoIBACVBmFkN8xWtyfoPBea5t6dAlhMoGGeC3koByU0iAt8XTsRak8MXn4PcqQuetGotl5JGBg9FT9GGVdZ8eXjiJ6VWCwie3HOfKkY/eex6Mg1P88qTxtQS3xVAPwTLXYJXLPJuc1BE7mSsQEjCzDMCaF7nhJwsL7aOPTx7ccjsoAyjpVd89wtT1H4NfZBCstWydpYTp0fxFu1v7Qz6d/+l+CgC6hLnSzFqTrNrXwqOv9ckiZVscUXnzcABanAwuiuNCCo8aiFmOoCI0yKRqcDC/joBQl9azu8rVvIL3GkdwWL3Nc2M+xrqDYWtlSc4WhK2T3y1dXom4cZHTgNmVcHQrwECgYEA9H38zyB6gDYSjRb6EPrAkfkOpJr+oZn8onJ3SI8X5OBsl9/MPo1sCmEniPk1H/yO/Ol9OMFSkVPFvVCebgR2he6QQqZu/VwVM8DDhzsDdj8KPbJQ/yKpJDvoNHVt0wAehxIybELOWHB1UYq1zd602sfiwg1jVyZGIzEPOAEz0b0CgYEAnM6teriibDkdqg8tmxgKdCJUS8CaP/h5/rB3kWOGfD0tJfVaBatovbvXGediJfNXE03vwGKhk/IGQuSEkrQ48cLAgYD/aF/2EaBLZYoQB8STvE6yy4RF1Ne5zR24KWnmxjt7URhIF3mCPWJV9oDGnfa/ANbRpGaOVIMjo5utXc0CgYA4zVSA4rDTPLzOnrn2W+uFfnGSeJgT/2ycaS+hYe1RNXrFRi9zkPO67Zt7zTo0dj7aL3zyRKfkL6xPMX29XbgTobtOYNCEeHJMlcpXjrRdMoQ0lUsQG4Nkca6fEXE0hmCRTP79+/9ouKfpC+r1K3qlIa9jGi0sQC4nWuyIPG9HmQKBgFRX6wIOm/bgRe96GIrKxJyw9myEnbN5AI2Y98dxJB5hfY5kSVaxWzZq+glJ5wYIvLZ6flIZ+1UromiKqDCM1fBcU9WUwEyxCRd0A/oK6BJ1jw2DuzIy5KjWnG8S5EMKXoIT7oGxMN3HkuFXqmtb2vmOhjB6W+s06qvUme/fxcGlAoGBANXdbNwnjdQ/WOP5dk8Y0ZDriaA6NzuDWjMK1hu1/VgwprJiMc5Rzhuu+47bMZyCEkRhiXM6xXe4eofRDKyhc2T0rQUd8LfGJeBVhiPN+6g8GTd6lML2DeRtdabAI75jddcfgARs4neRPPvAx6Fw/AhPDfPlMP8MCLwpkprJGarr
a06ed409-15d3-4022-869c-788c4bd23b46	c51ab623-c02b-4a5a-ada5-e61df41de012	allow-default-scopes	true
fade3e67-b3fc-4ef5-85aa-379a7e0227d5	68afb40c-9a0c-4555-b35c-c9d955ced156	max-clients	200
743293bc-ff9b-4466-ba6c-082cc8cc92b7	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	saml-user-property-mapper
4152dcc0-bf41-4dbc-adf1-49394f2be0d7	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	saml-role-list-mapper
3f3f4b6a-a07e-4593-b9e8-baa0d035a5c2	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	oidc-full-name-mapper
41609007-2e6f-46e9-9dc8-1b98c1416569	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	oidc-address-mapper
375a8910-37b7-48d3-bd13-a764fff41ca8	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
3fd53db6-b178-4ef3-b7f5-d15a13d4ab02	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
083eb4aa-8c3e-4555-ad3e-c8c922fd0659	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	saml-user-attribute-mapper
f7d24a91-eb96-4af3-b0c2-b5ab5f2c455e	fa445be6-69b7-40a2-b065-d9c48f59df4b	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
ef2f0a18-4125-4e8e-94d7-853d6477b9fd	53faefab-0ef6-4773-9e47-13a39c9c4d3d	allow-default-scopes	true
d5004c16-e9ee-49b4-9f20-e76dce4ce7a7	c528b20c-b427-4082-92d9-583e5e63c494	host-sending-registration-request-must-match	true
8f36f38a-b2dd-460e-8d61-4e0a4bbdfc01	c528b20c-b427-4082-92d9-583e5e63c494	client-uris-must-match	true
3ff34dd1-4dbc-444e-a1eb-d7130d300ce5	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	saml-role-list-mapper
fc414254-05ca-4986-ae47-713e5f4c4475	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	saml-user-property-mapper
50ed6b7b-a6c0-445b-a68a-0163993c1545	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	oidc-address-mapper
8e44d6f1-fdb2-4b96-a154-fb2291d8dd6a	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
02dbe7a9-ba67-4c09-8711-bba7126b3792	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	saml-user-attribute-mapper
28ad730f-d1cf-46ae-b47f-558688d1af0b	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
d78d3810-0af4-4fae-91c8-14dbeabbfbbe	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
57dbd816-c0ac-458a-a939-723d30ee27ac	ef599fb9-3d6e-45d3-ae29-969be85ec6cc	allowed-protocol-mapper-types	oidc-full-name-mapper
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.composite_role (composite, child_role) FROM stdin;
fb175756-86a1-408c-89ce-c122f1be393f	b6b3f88e-b3fd-47fb-af3a-e1e310dfc7e8
fb175756-86a1-408c-89ce-c122f1be393f	c354c0bb-4200-4a83-bd88-54eef04e5731
fb175756-86a1-408c-89ce-c122f1be393f	8879bc04-ded1-4ee7-983b-aa26a91bfa65
fb175756-86a1-408c-89ce-c122f1be393f	16e0283c-d2b5-4b1f-94b9-8f597b7a499b
fb175756-86a1-408c-89ce-c122f1be393f	4a95c705-40f4-4f73-8d33-f4195b2a1fe6
fb175756-86a1-408c-89ce-c122f1be393f	a7ee60c6-7834-4ad4-8b37-34e1f9629506
fb175756-86a1-408c-89ce-c122f1be393f	4d0d5d3c-4fad-4e6d-b7d7-d45a0b2abbd9
fb175756-86a1-408c-89ce-c122f1be393f	30735d79-1153-4656-bc33-00427bc2046b
fb175756-86a1-408c-89ce-c122f1be393f	689c173d-48c3-4ef7-a40a-0204c3ff1e21
fb175756-86a1-408c-89ce-c122f1be393f	41a1158c-6a74-4f58-b9cc-927233ffbb21
fb175756-86a1-408c-89ce-c122f1be393f	92126a67-5f0a-4ad0-9c3b-3de2b4357af6
fb175756-86a1-408c-89ce-c122f1be393f	a6360aab-2a7e-4a2e-a728-845f2974e311
fb175756-86a1-408c-89ce-c122f1be393f	bff949fb-84b3-4ffd-804a-f94c36a8160d
fb175756-86a1-408c-89ce-c122f1be393f	9650d160-ca55-4d3e-9b50-89490e532b3b
fb175756-86a1-408c-89ce-c122f1be393f	721e47e4-e078-4259-9422-7f380d0a7a8c
fb175756-86a1-408c-89ce-c122f1be393f	27951e1c-7cc3-44b0-8e48-9ad5eff021d3
fb175756-86a1-408c-89ce-c122f1be393f	bbd00da0-fe14-4a4d-8505-0dd8a30df965
fb175756-86a1-408c-89ce-c122f1be393f	34098af9-fefa-4cce-8ed9-0e20159c720c
16e0283c-d2b5-4b1f-94b9-8f597b7a499b	34098af9-fefa-4cce-8ed9-0e20159c720c
16e0283c-d2b5-4b1f-94b9-8f597b7a499b	721e47e4-e078-4259-9422-7f380d0a7a8c
4a95c705-40f4-4f73-8d33-f4195b2a1fe6	27951e1c-7cc3-44b0-8e48-9ad5eff021d3
ab5d210f-5caf-4449-aed3-502dd36e7ebe	e3d02bc5-e9ff-47b1-ac9c-0914fa10b2dc
fb175756-86a1-408c-89ce-c122f1be393f	59dde511-cf7b-4eb0-9129-6bea1062c16a
fb175756-86a1-408c-89ce-c122f1be393f	47c9fe55-c305-4c94-b042-4bbeeda3e205
fb175756-86a1-408c-89ce-c122f1be393f	f986a784-40b4-4994-a56e-f90788487faa
fb175756-86a1-408c-89ce-c122f1be393f	dae5be1e-9651-4168-ad6d-61bfcc3233d4
fb175756-86a1-408c-89ce-c122f1be393f	599b4e3d-1eb6-4a2f-bc74-2df9c41f6579
fb175756-86a1-408c-89ce-c122f1be393f	5cf439a4-22d4-4d34-95dd-402f1289b159
fb175756-86a1-408c-89ce-c122f1be393f	91b27881-077d-4ec6-a7a6-2cf8def9456b
fb175756-86a1-408c-89ce-c122f1be393f	3dde9786-ace8-455f-92b0-d2f3829fbef8
fb175756-86a1-408c-89ce-c122f1be393f	80191309-34ee-48f0-a73f-b5334e819fac
fb175756-86a1-408c-89ce-c122f1be393f	d996cf8e-26ac-4f4d-89a6-9cb023817000
fb175756-86a1-408c-89ce-c122f1be393f	bc798d73-b7fd-4bb1-a733-c92419dd2911
fb175756-86a1-408c-89ce-c122f1be393f	c5e2af38-a6c6-48a5-b304-2837ba18f6fe
fb175756-86a1-408c-89ce-c122f1be393f	fed6a643-ca1b-4621-bd8b-30351ea1d422
fb175756-86a1-408c-89ce-c122f1be393f	2837cbab-bd07-4ccd-9c7e-c9042b91ae02
fb175756-86a1-408c-89ce-c122f1be393f	36c7cba2-7937-4c98-822e-a9b875f64d30
fb175756-86a1-408c-89ce-c122f1be393f	49e5ce5d-8055-4f18-954a-007b0862203d
fb175756-86a1-408c-89ce-c122f1be393f	705a11ad-9d1d-4c70-bc37-4951ce1ef6df
fb175756-86a1-408c-89ce-c122f1be393f	1d829c95-6e8f-4c5d-bdd1-ed903548275a
dae5be1e-9651-4168-ad6d-61bfcc3233d4	36c7cba2-7937-4c98-822e-a9b875f64d30
dae5be1e-9651-4168-ad6d-61bfcc3233d4	1d829c95-6e8f-4c5d-bdd1-ed903548275a
599b4e3d-1eb6-4a2f-bc74-2df9c41f6579	49e5ce5d-8055-4f18-954a-007b0862203d
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	5e8e07b8-5ff6-4560-b5e5-b2219c7251f2
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	f7404ae9-31e0-48e9-a2fc-084e8f18817f
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	11ccb457-eb92-4d24-8bc6-1fa66d13abd5
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	7a8312c7-0e31-498a-93d6-85d89d32f412
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	158cf8a6-d73e-4871-a132-f096bf0117c0
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	6d4def63-fe6e-42aa-a3f6-6744a2b92d65
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	b9891135-a734-4eb9-b97d-3bffefb1f9f5
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	fb3000e1-5d76-4fe8-a818-b89ee8765099
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	446c9866-3035-44a7-aad1-4c0c14404316
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	08bca504-b511-46cd-9968-416409ff6ac2
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	7b75f3a1-86ed-430f-8a8e-70a118de2548
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	03e5455a-d145-44ff-b7bb-5a9745773208
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	3a8920f5-460b-428d-85dd-c7432fe757b2
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	c0fdf6fa-de33-415c-bf81-020e56a80030
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	faca6b6f-b35e-45cf-8f7b-fde94f76ff77
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	811d50c3-d208-4cd3-9793-57488696b5f6
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	2f42038e-4a53-41b4-ae37-2c2612c1b908
11ccb457-eb92-4d24-8bc6-1fa66d13abd5	2f42038e-4a53-41b4-ae37-2c2612c1b908
11ccb457-eb92-4d24-8bc6-1fa66d13abd5	c0fdf6fa-de33-415c-bf81-020e56a80030
7a8312c7-0e31-498a-93d6-85d89d32f412	faca6b6f-b35e-45cf-8f7b-fde94f76ff77
fb175756-86a1-408c-89ce-c122f1be393f	855a5d8d-b87d-4e6f-9d09-fd80d3199bba
1cbf3fee-dada-4fb5-b2c0-583fbc1ee8bf	36c5f387-c000-413e-a52a-66ca3335211d
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	6878ad97-f319-4a14-9eb9-6296e7ae4fc0
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.credential (id, device, hash_iterations, salt, type, value, user_id, created_date, counter, digits, period, algorithm) FROM stdin;
0805b85d-ddb5-4657-9097-47f823c5ae1d	\N	27500	\\xe70dee6b4df7e48972522aa5b13adcc9	password	asP36NE+6pVO6MCJJp+VWmhefquidwfJWVgu/8cCuRhIx8nBu9QtdmyAC4/2wju4TGUPTs3lRMy5Hkr7YIfa9A==	d1f07e02-268a-4b1c-b8a5-0c049149038b	\N	0	0	0	pbkdf2-sha256
fb84881a-aa4b-44e0-9fc7-fce0d5a59db7	\N	27500	\\xfcf809c2257b95438be8ca1e3100a21b	password	1jZFM07bUYxZgVgPJhylUjpVHtTrZ7Fcesciu53f/L1VcjoFvyVozcLukeEFe4+VjzzdsemNJdvOMyedbo6n1Q==	b4d7c216-78b4-4dc3-ae02-c93277e5c02c	1693396524189	0	0	0	pbkdf2-sha256
\.


--
-- Data for Name: credential_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2023-08-30 11:38:19.5393	1	EXECUTED	7:4e70412f24a3f382c82183742ec79317	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	3395499327
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2023-08-30 11:38:19.552845	2	MARK_RAN	7:cb16724583e9675711801c6875114f28	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	3395499327
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2023-08-30 11:38:19.577341	3	EXECUTED	7:0310eb8ba07cec616460794d42ade0fa	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	3.5.4	\N	\N	3395499327
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2023-08-30 11:38:19.580255	4	EXECUTED	7:5d25857e708c3233ef4439df1f93f012	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	3.5.4	\N	\N	3395499327
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2023-08-30 11:38:19.634995	5	EXECUTED	7:c7a54a1041d58eb3817a4a883b4d4e84	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	3395499327
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2023-08-30 11:38:19.637916	6	MARK_RAN	7:2e01012df20974c1c2a605ef8afe25b7	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	3395499327
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2023-08-30 11:38:19.687931	7	EXECUTED	7:0f08df48468428e0f30ee59a8ec01a41	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	3395499327
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2023-08-30 11:38:19.690883	8	MARK_RAN	7:a77ea2ad226b345e7d689d366f185c8c	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	3395499327
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2023-08-30 11:38:19.694668	9	EXECUTED	7:a3377a2059aefbf3b90ebb4c4cc8e2ab	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	3.5.4	\N	\N	3395499327
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2023-08-30 11:38:19.757558	10	EXECUTED	7:04c1dbedc2aa3e9756d1a1668e003451	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	3.5.4	\N	\N	3395499327
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2023-08-30 11:38:19.790176	11	EXECUTED	7:36ef39ed560ad07062d956db861042ba	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	3395499327
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2023-08-30 11:38:19.792648	12	MARK_RAN	7:d909180b2530479a716d3f9c9eaea3d7	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	3395499327
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2023-08-30 11:38:19.805312	13	EXECUTED	7:cf12b04b79bea5152f165eb41f3955f6	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	3395499327
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2023-08-30 11:38:19.820459	14	EXECUTED	7:7e32c8f05c755e8675764e7d5f514509	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	3.5.4	\N	\N	3395499327
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2023-08-30 11:38:19.822325	15	MARK_RAN	7:980ba23cc0ec39cab731ce903dd01291	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	3395499327
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2023-08-30 11:38:19.824019	16	MARK_RAN	7:2fa220758991285312eb84f3b4ff5336	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	3.5.4	\N	\N	3395499327
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2023-08-30 11:38:19.825612	17	EXECUTED	7:d41d8cd98f00b204e9800998ecf8427e	empty		\N	3.5.4	\N	\N	3395499327
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2023-08-30 11:38:19.858732	18	EXECUTED	7:91ace540896df890cc00a0490ee52bbc	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	3.5.4	\N	\N	3395499327
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2023-08-30 11:38:19.892365	19	EXECUTED	7:c31d1646dfa2618a9335c00e07f89f24	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	3395499327
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2023-08-30 11:38:19.896945	20	EXECUTED	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	3395499327
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2023-08-30 11:38:20.189701	45	EXECUTED	7:6a48ce645a3525488a90fbf76adf3bb3	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	3395499327
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2023-08-30 11:38:19.899115	21	MARK_RAN	7:f987971fe6b37d963bc95fee2b27f8df	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	3395499327
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2023-08-30 11:38:19.901386	22	MARK_RAN	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	3395499327
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2023-08-30 11:38:19.9171	23	EXECUTED	7:ed2dc7f799d19ac452cbcda56c929e47	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	3.5.4	\N	\N	3395499327
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2023-08-30 11:38:19.921148	24	EXECUTED	7:80b5db88a5dda36ece5f235be8757615	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	3395499327
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2023-08-30 11:38:19.922935	25	MARK_RAN	7:1437310ed1305a9b93f8848f301726ce	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	3395499327
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2023-08-30 11:38:19.942619	26	EXECUTED	7:b82ffb34850fa0836be16deefc6a87c4	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	3.5.4	\N	\N	3395499327
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2023-08-30 11:38:19.989041	27	EXECUTED	7:9cc98082921330d8d9266decdd4bd658	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	3.5.4	\N	\N	3395499327
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2023-08-30 11:38:19.99208	28	EXECUTED	7:03d64aeed9cb52b969bd30a7ac0db57e	update tableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	3395499327
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2023-08-30 11:38:20.035384	29	EXECUTED	7:f1f9fd8710399d725b780f463c6b21cd	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	3.5.4	\N	\N	3395499327
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2023-08-30 11:38:20.045813	30	EXECUTED	7:53188c3eb1107546e6f765835705b6c1	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	3.5.4	\N	\N	3395499327
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2023-08-30 11:38:20.058567	31	EXECUTED	7:d6e6f3bc57a0c5586737d1351725d4d4	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	3.5.4	\N	\N	3395499327
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2023-08-30 11:38:20.062658	32	EXECUTED	7:454d604fbd755d9df3fd9c6329043aa5	customChange		\N	3.5.4	\N	\N	3395499327
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2023-08-30 11:38:20.067256	33	EXECUTED	7:57e98a3077e29caf562f7dbf80c72600	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	3395499327
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2023-08-30 11:38:20.069122	34	MARK_RAN	7:e4c7e8f2256210aee71ddc42f538b57a	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	3395499327
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2023-08-30 11:38:20.088208	35	EXECUTED	7:09a43c97e49bc626460480aa1379b522	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	3395499327
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2023-08-30 11:38:20.092245	36	EXECUTED	7:26bfc7c74fefa9126f2ce702fb775553	addColumn tableName=REALM		\N	3.5.4	\N	\N	3395499327
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2023-08-30 11:38:20.096569	37	EXECUTED	7:a161e2ae671a9020fff61e996a207377	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	3395499327
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2023-08-30 11:38:20.099302	38	EXECUTED	7:37fc1781855ac5388c494f1442b3f717	addColumn tableName=FED_USER_CONSENT		\N	3.5.4	\N	\N	3395499327
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2023-08-30 11:38:20.101973	39	EXECUTED	7:13a27db0dae6049541136adad7261d27	addColumn tableName=IDENTITY_PROVIDER		\N	3.5.4	\N	\N	3395499327
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2023-08-30 11:38:20.103605	40	MARK_RAN	7:550300617e3b59e8af3a6294df8248a3	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	3395499327
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2023-08-30 11:38:20.105234	41	MARK_RAN	7:e3a9482b8931481dc2772a5c07c44f17	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	3395499327
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2023-08-30 11:38:20.109364	42	EXECUTED	7:72b07d85a2677cb257edb02b408f332d	customChange		\N	3.5.4	\N	\N	3395499327
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2023-08-30 11:38:20.184032	43	EXECUTED	7:a72a7858967bd414835d19e04d880312	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	3.5.4	\N	\N	3395499327
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2023-08-30 11:38:20.186964	44	EXECUTED	7:94edff7cf9ce179e7e85f0cd78a3cf2c	addColumn tableName=USER_ENTITY		\N	3.5.4	\N	\N	3395499327
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2023-08-30 11:38:20.192734	46	EXECUTED	7:e64b5dcea7db06077c6e57d3b9e5ca14	customChange		\N	3.5.4	\N	\N	3395499327
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2023-08-30 11:38:20.19399	47	MARK_RAN	7:fd8cf02498f8b1e72496a20afc75178c	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	3395499327
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2023-08-30 11:38:20.213389	48	EXECUTED	7:542794f25aa2b1fbabb7e577d6646319	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	3.5.4	\N	\N	3395499327
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2023-08-30 11:38:20.216227	49	EXECUTED	7:edad604c882df12f74941dac3cc6d650	addColumn tableName=REALM		\N	3.5.4	\N	\N	3395499327
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2023-08-30 11:38:20.23836	50	EXECUTED	7:0f88b78b7b46480eb92690cbf5e44900	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	3.5.4	\N	\N	3395499327
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2023-08-30 11:38:20.254353	51	EXECUTED	7:d560e43982611d936457c327f872dd59	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	3.5.4	\N	\N	3395499327
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2023-08-30 11:38:20.256352	52	EXECUTED	7:c155566c42b4d14ef07059ec3b3bbd8e	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	3.5.4	\N	\N	3395499327
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2023-08-30 11:38:20.258132	53	EXECUTED	7:b40376581f12d70f3c89ba8ddf5b7dea	update tableName=REALM		\N	3.5.4	\N	\N	3395499327
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2023-08-30 11:38:20.259855	54	EXECUTED	7:a1132cc395f7b95b3646146c2e38f168	update tableName=CLIENT		\N	3.5.4	\N	\N	3395499327
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2023-08-30 11:38:20.263366	55	EXECUTED	7:d8dc5d89c789105cfa7ca0e82cba60af	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	3.5.4	\N	\N	3395499327
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2023-08-30 11:38:20.266249	56	EXECUTED	7:7822e0165097182e8f653c35517656a3	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	3.5.4	\N	\N	3395499327
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2023-08-30 11:38:20.277304	57	EXECUTED	7:c6538c29b9c9a08f9e9ea2de5c2b6375	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	3.5.4	\N	\N	3395499327
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2023-08-30 11:38:20.329375	58	EXECUTED	7:6d4893e36de22369cf73bcb051ded875	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	3.5.4	\N	\N	3395499327
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2023-08-30 11:38:20.344067	59	EXECUTED	7:57960fc0b0f0dd0563ea6f8b2e4a1707	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	3.5.4	\N	\N	3395499327
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2023-08-30 11:38:20.347445	60	EXECUTED	7:2b4b8bff39944c7097977cc18dbceb3b	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	3395499327
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2023-08-30 11:38:20.352417	61	EXECUTED	7:2aa42a964c59cd5b8ca9822340ba33a8	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	3.5.4	\N	\N	3395499327
authz-4.2.0.Final-KEYCLOAK-9944	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2023-08-30 11:38:20.355725	62	EXECUTED	7:9ac9e58545479929ba23f4a3087a0346	addPrimaryKey constraintName=CONSTRAINT_RESOUR_URIS_PK, tableName=RESOURCE_URIS		\N	3.5.4	\N	\N	3395499327
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2023-08-30 11:38:20.357834	63	EXECUTED	7:14d407c35bc4fe1976867756bcea0c36	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	3395499327
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2023-08-30 11:38:20.359734	64	EXECUTED	7:241a8030c748c8548e346adee548fa93	update tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	3395499327
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2023-08-30 11:38:20.361397	65	EXECUTED	7:7d3182f65a34fcc61e8d23def037dc3f	update tableName=RESOURCE_SERVER_RESOURCE		\N	3.5.4	\N	\N	3395499327
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2023-08-30 11:38:20.368497	66	EXECUTED	7:b30039e00a0b9715d430d1b0636728fa	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	3.5.4	\N	\N	3395499327
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2023-08-30 11:38:20.371665	67	EXECUTED	7:3797315ca61d531780f8e6f82f258159	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	3.5.4	\N	\N	3395499327
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2023-08-30 11:38:20.374239	68	EXECUTED	7:c7aa4c8d9573500c2d347c1941ff0301	addColumn tableName=REALM		\N	3.5.4	\N	\N	3395499327
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2023-08-30 11:38:20.380038	69	EXECUTED	7:b207faee394fc074a442ecd42185a5dd	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	3.5.4	\N	\N	3395499327
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2023-08-30 11:38:20.383132	70	EXECUTED	7:ab9a9762faaba4ddfa35514b212c4922	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	3.5.4	\N	\N	3395499327
authz-7.0.0-KEYCLOAK-10443	psilva@redhat.com	META-INF/jpa-changelog-authz-7.0.0.xml	2023-08-30 11:38:20.385331	71	EXECUTED	7:b9710f74515a6ccb51b72dc0d19df8c4	addColumn tableName=RESOURCE_SERVER		\N	3.5.4	\N	\N	3395499327
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
1000	f	\N	\N
1001	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
master	a22c9db1-3865-4562-aaf9-52a915fd2921	f
master	8a83729e-8538-4988-b438-eee87d810358	t
master	5409d19b-5095-4145-9edb-0175256d59b4	t
master	159ff0c7-f724-408b-8298-ab27e1304ba4	t
master	0617a61c-2ce7-4f90-9c5a-5362af0b4c63	f
master	e100bf70-1e86-4077-a735-37c1c58f657d	f
master	87f7a2d0-5faf-4b8e-a913-a6deb70130d9	t
master	57e73925-0ec4-4b99-b969-518226e19c21	t
master	1ee08abf-5282-4783-8eca-e889e7563ca9	f
demo-realm	b056306b-82ba-4751-99df-6eeb87a74dce	f
demo-realm	1ac840b4-2517-410d-8219-eae3b717a2a4	t
demo-realm	69ebabb2-0ced-49ad-b8cc-99ef083ea52b	t
demo-realm	67754b0a-38a9-458e-9c59-3f1fdcd2439b	t
demo-realm	7031920c-9eb7-4389-86fb-f2cd3141f51d	f
demo-realm	f4566753-b0d7-477b-9028-4fd25f418306	f
demo-realm	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc	t
demo-realm	ac7bf87c-385e-41ec-8596-44c38dc6850b	t
demo-realm	b058e660-4520-4503-8f2a-0e3cbac25da8	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id) FROM stdin;
\.


--
-- Data for Name: fed_credential_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_credential (id, device, hash_iterations, salt, type, value, created_date, counter, digits, period, algorithm, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only) FROM stdin;
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.keycloak_group (id, name, parent_group, realm_id) FROM stdin;
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
fb175756-86a1-408c-89ce-c122f1be393f	master	f	${role_admin}	admin	master	\N	master
b6b3f88e-b3fd-47fb-af3a-e1e310dfc7e8	master	f	${role_create-realm}	create-realm	master	\N	master
c354c0bb-4200-4a83-bd88-54eef04e5731	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_create-client}	create-client	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
8879bc04-ded1-4ee7-983b-aa26a91bfa65	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_view-realm}	view-realm	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
16e0283c-d2b5-4b1f-94b9-8f597b7a499b	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_view-users}	view-users	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
4a95c705-40f4-4f73-8d33-f4195b2a1fe6	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_view-clients}	view-clients	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
a7ee60c6-7834-4ad4-8b37-34e1f9629506	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_view-events}	view-events	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
4d0d5d3c-4fad-4e6d-b7d7-d45a0b2abbd9	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_view-identity-providers}	view-identity-providers	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
30735d79-1153-4656-bc33-00427bc2046b	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_view-authorization}	view-authorization	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
689c173d-48c3-4ef7-a40a-0204c3ff1e21	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_manage-realm}	manage-realm	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
41a1158c-6a74-4f58-b9cc-927233ffbb21	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_manage-users}	manage-users	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
92126a67-5f0a-4ad0-9c3b-3de2b4357af6	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_manage-clients}	manage-clients	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
a6360aab-2a7e-4a2e-a728-845f2974e311	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_manage-events}	manage-events	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
bff949fb-84b3-4ffd-804a-f94c36a8160d	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_manage-identity-providers}	manage-identity-providers	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
9650d160-ca55-4d3e-9b50-89490e532b3b	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_manage-authorization}	manage-authorization	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
721e47e4-e078-4259-9422-7f380d0a7a8c	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_query-users}	query-users	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
27951e1c-7cc3-44b0-8e48-9ad5eff021d3	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_query-clients}	query-clients	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
bbd00da0-fe14-4a4d-8505-0dd8a30df965	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_query-realms}	query-realms	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
34098af9-fefa-4cce-8ed9-0e20159c720c	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_query-groups}	query-groups	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
d7e91971-22d9-4051-b421-6775f9ddcc3a	a831efff-56c4-4eb0-b6cb-d4816b326de8	t	${role_view-profile}	view-profile	master	a831efff-56c4-4eb0-b6cb-d4816b326de8	\N
ab5d210f-5caf-4449-aed3-502dd36e7ebe	a831efff-56c4-4eb0-b6cb-d4816b326de8	t	${role_manage-account}	manage-account	master	a831efff-56c4-4eb0-b6cb-d4816b326de8	\N
e3d02bc5-e9ff-47b1-ac9c-0914fa10b2dc	a831efff-56c4-4eb0-b6cb-d4816b326de8	t	${role_manage-account-links}	manage-account-links	master	a831efff-56c4-4eb0-b6cb-d4816b326de8	\N
a91eedb1-0e37-467b-8b2d-9e8bc5529909	46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	t	${role_read-token}	read-token	master	46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	\N
59dde511-cf7b-4eb0-9129-6bea1062c16a	e96afb04-c8e3-4d09-b74d-06fa364e582f	t	${role_impersonation}	impersonation	master	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
34c8ae53-e5dd-4a42-bda1-9fe88860caa2	master	f	${role_offline-access}	offline_access	master	\N	master
8323e721-a4bd-496c-bdbc-39746fc7552e	master	f	${role_uma_authorization}	uma_authorization	master	\N	master
47c9fe55-c305-4c94-b042-4bbeeda3e205	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_create-client}	create-client	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
f986a784-40b4-4994-a56e-f90788487faa	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_view-realm}	view-realm	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
dae5be1e-9651-4168-ad6d-61bfcc3233d4	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_view-users}	view-users	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
599b4e3d-1eb6-4a2f-bc74-2df9c41f6579	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_view-clients}	view-clients	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
5cf439a4-22d4-4d34-95dd-402f1289b159	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_view-events}	view-events	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
91b27881-077d-4ec6-a7a6-2cf8def9456b	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_view-identity-providers}	view-identity-providers	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
3dde9786-ace8-455f-92b0-d2f3829fbef8	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_view-authorization}	view-authorization	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
80191309-34ee-48f0-a73f-b5334e819fac	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_manage-realm}	manage-realm	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
d996cf8e-26ac-4f4d-89a6-9cb023817000	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_manage-users}	manage-users	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
bc798d73-b7fd-4bb1-a733-c92419dd2911	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_manage-clients}	manage-clients	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
c5e2af38-a6c6-48a5-b304-2837ba18f6fe	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_manage-events}	manage-events	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
fed6a643-ca1b-4621-bd8b-30351ea1d422	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_manage-identity-providers}	manage-identity-providers	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
2837cbab-bd07-4ccd-9c7e-c9042b91ae02	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_manage-authorization}	manage-authorization	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
36c7cba2-7937-4c98-822e-a9b875f64d30	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_query-users}	query-users	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
49e5ce5d-8055-4f18-954a-007b0862203d	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_query-clients}	query-clients	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
705a11ad-9d1d-4c70-bc37-4951ce1ef6df	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_query-realms}	query-realms	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
1d829c95-6e8f-4c5d-bdd1-ed903548275a	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_query-groups}	query-groups	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
d07c3c36-ff00-4b9d-8a25-517c00e7c1aa	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_realm-admin}	realm-admin	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
5e8e07b8-5ff6-4560-b5e5-b2219c7251f2	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_create-client}	create-client	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
f7404ae9-31e0-48e9-a2fc-084e8f18817f	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_view-realm}	view-realm	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
11ccb457-eb92-4d24-8bc6-1fa66d13abd5	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_view-users}	view-users	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
7a8312c7-0e31-498a-93d6-85d89d32f412	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_view-clients}	view-clients	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
158cf8a6-d73e-4871-a132-f096bf0117c0	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_view-events}	view-events	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
6d4def63-fe6e-42aa-a3f6-6744a2b92d65	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_view-identity-providers}	view-identity-providers	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
b9891135-a734-4eb9-b97d-3bffefb1f9f5	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_view-authorization}	view-authorization	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
fb3000e1-5d76-4fe8-a818-b89ee8765099	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_manage-realm}	manage-realm	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
446c9866-3035-44a7-aad1-4c0c14404316	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_manage-users}	manage-users	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
08bca504-b511-46cd-9968-416409ff6ac2	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_manage-clients}	manage-clients	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
7b75f3a1-86ed-430f-8a8e-70a118de2548	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_manage-events}	manage-events	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
03e5455a-d145-44ff-b7bb-5a9745773208	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_manage-identity-providers}	manage-identity-providers	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
3a8920f5-460b-428d-85dd-c7432fe757b2	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_manage-authorization}	manage-authorization	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
c0fdf6fa-de33-415c-bf81-020e56a80030	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_query-users}	query-users	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
faca6b6f-b35e-45cf-8f7b-fde94f76ff77	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_query-clients}	query-clients	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
811d50c3-d208-4cd3-9793-57488696b5f6	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_query-realms}	query-realms	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
2f42038e-4a53-41b4-ae37-2c2612c1b908	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_query-groups}	query-groups	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
b5fe97e3-364e-4d57-8039-a29c8e950ab8	438afdec-0eca-4e17-89f1-8133076985b3	t	${role_view-profile}	view-profile	demo-realm	438afdec-0eca-4e17-89f1-8133076985b3	\N
1cbf3fee-dada-4fb5-b2c0-583fbc1ee8bf	438afdec-0eca-4e17-89f1-8133076985b3	t	${role_manage-account}	manage-account	demo-realm	438afdec-0eca-4e17-89f1-8133076985b3	\N
36c5f387-c000-413e-a52a-66ca3335211d	438afdec-0eca-4e17-89f1-8133076985b3	t	${role_manage-account-links}	manage-account-links	demo-realm	438afdec-0eca-4e17-89f1-8133076985b3	\N
855a5d8d-b87d-4e6f-9d09-fd80d3199bba	ca12f299-0359-4701-ae0f-5c90768b7b34	t	${role_impersonation}	impersonation	master	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
6878ad97-f319-4a14-9eb9-6296e7ae4fc0	9656e394-8a00-4a9a-902f-a569910c789a	t	${role_impersonation}	impersonation	demo-realm	9656e394-8a00-4a9a-902f-a569910c789a	\N
a910b5d7-6983-4f76-96ec-a694957175bb	38f6fa40-e74a-4c21-930c-b86be2c436af	t	${role_read-token}	read-token	demo-realm	38f6fa40-e74a-4c21-930c-b86be2c436af	\N
3169f3f9-83ae-4cfd-8fa9-34b8b37d68a9	demo-realm	f	${role_offline-access}	offline_access	demo-realm	\N	demo-realm
19320043-3c40-4762-a607-662c8a105cf8	demo-realm	f	${role_uma_authorization}	uma_authorization	demo-realm	\N	demo-realm
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.migration_model (id, version) FROM stdin;
SINGLETON	6.0.0
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
d960a59d-a1f8-4a49-9144-3b2d291e2328	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	e96afb04-c8e3-4d09-b74d-06fa364e582f	\N
9cfc4e6e-f459-40f0-92c6-ccfdaacd5fc9	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	a831efff-56c4-4eb0-b6cb-d4816b326de8	\N
05ede471-1a6d-4a48-9550-c687332bb24d	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	46b1d7ef-1c1c-4d81-8800-81c7dbff4da7	\N
6f2af80c-3d52-4a27-a4df-f70fcc28f8bb	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	5705c8e6-4bc0-4531-9edc-773d8295af8f	\N
33df8532-0f8e-4eca-85ef-f7c2a50a1806	locale	openid-connect	oidc-usermodel-attribute-mapper	5705c8e6-4bc0-4531-9edc-773d8295af8f	\N
6e2bd325-c812-4e20-b8ed-0f483a8c7ed1	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	022de84b-3e7b-459e-84e1-93f6dacc41ce	\N
2ec897cc-0873-4923-8b6b-c50fa35d21e1	role list	saml	saml-role-list-mapper	\N	8a83729e-8538-4988-b438-eee87d810358
c5948a8c-5ac2-4949-bd39-418a6c1d5f9f	full name	openid-connect	oidc-full-name-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	family name	openid-connect	oidc-usermodel-property-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	given name	openid-connect	oidc-usermodel-property-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
a584c389-4eaa-447b-8d97-ccfdc491553d	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
b05fb1a0-de63-49be-b7b7-a49aa022bb70	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
79739665-e21e-412c-8e3a-bb3c9809980b	username	openid-connect	oidc-usermodel-property-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
a20a943f-14fd-4d1c-90b3-da329549fe43	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
8399b9e5-146d-46c6-9e9a-04bb65bce349	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
1f04f149-b5a1-4e53-a5c9-afbb7f552170	website	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
e0d19512-090d-471e-8537-82405bc69bd7	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
899f29f9-73b5-4ac4-8504-df853888c382	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
41103857-e637-4856-801d-221c1e158a3e	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
44fe0133-3b68-4418-a00e-9f8217d90a77	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
193a2f41-b78b-4b27-95ef-aee1e5f055ff	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	5409d19b-5095-4145-9edb-0175256d59b4
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	email	openid-connect	oidc-usermodel-property-mapper	\N	159ff0c7-f724-408b-8298-ab27e1304ba4
679aa3f4-8a10-4581-ba44-12fb09c6b39a	email verified	openid-connect	oidc-usermodel-property-mapper	\N	159ff0c7-f724-408b-8298-ab27e1304ba4
973514cc-2f86-49d7-a6eb-53f6d828ce20	address	openid-connect	oidc-address-mapper	\N	0617a61c-2ce7-4f90-9c5a-5362af0b4c63
c2c5d853-8fe5-41c9-8453-7568ec4b3213	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	e100bf70-1e86-4077-a735-37c1c58f657d
b1f6cfce-402f-438f-a082-2a03dccd7847	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	e100bf70-1e86-4077-a735-37c1c58f657d
3f7a7abd-67f6-4139-80c1-2200bf06b8e2	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	87f7a2d0-5faf-4b8e-a913-a6deb70130d9
346514f0-95bd-4ab1-a77f-eca5ca2d253a	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	87f7a2d0-5faf-4b8e-a913-a6deb70130d9
2dc95714-9d2b-4090-9f35-4f82ac9916ff	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	87f7a2d0-5faf-4b8e-a913-a6deb70130d9
eeb91493-d243-4169-aa98-2a642e79f3dd	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	57e73925-0ec4-4b99-b969-518226e19c21
617d85de-3838-456d-b2da-6ae1f3fd93e3	upn	openid-connect	oidc-usermodel-property-mapper	\N	1ee08abf-5282-4783-8eca-e889e7563ca9
5069b46f-7a04-4a03-ab55-f2cbea898931	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	1ee08abf-5282-4783-8eca-e889e7563ca9
ced608e0-0509-4028-a8aa-16bf29c15f42	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	ca12f299-0359-4701-ae0f-5c90768b7b34	\N
502a08bb-7873-45f6-8290-3e634597ea30	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	9656e394-8a00-4a9a-902f-a569910c789a	\N
f64be64d-5ed5-4394-b6d5-dd54b55575da	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	438afdec-0eca-4e17-89f1-8133076985b3	\N
d8a5a3a8-7c20-4c9f-8630-8dfc353e61cc	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	38f6fa40-e74a-4c21-930c-b86be2c436af	\N
628acee6-934d-4f10-ab17-f24901180cd2	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	864375cb-3edf-44ed-85b0-8fd316506d30	\N
da71f74f-b976-4640-9219-9821ed579aad	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	bfaebaf8-04b9-4a5e-b688-7f4116bd8fbd	\N
d8fc54d1-40e1-4b84-ad33-5ac289d691e0	role list	saml	saml-role-list-mapper	\N	1ac840b4-2517-410d-8219-eae3b717a2a4
d3d4025a-3c30-4a50-b519-2b0d6f502548	full name	openid-connect	oidc-full-name-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
9b91c18d-b477-400a-9ef0-6912cc1a42fd	family name	openid-connect	oidc-usermodel-property-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
dec28b68-100a-48f2-9c90-bbe49848a444	given name	openid-connect	oidc-usermodel-property-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
cc90cc89-2468-44f3-a0f6-0b804321c3c4	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
e3f2f18d-7483-4152-8e68-782dc568e761	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	username	openid-connect	oidc-usermodel-property-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
ee5ebec5-c241-4144-86c4-65fc8d516bd8	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
e8a7d270-585b-477e-a04a-c1cf51077a66	website	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
eb035e76-805e-4029-a973-83276212d771	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
2a5502f2-4ec1-4dbe-874d-f378fb733040	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
77c7dd72-25ab-4448-ba88-24475e5c7047	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	69ebabb2-0ced-49ad-b8cc-99ef083ea52b
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	email	openid-connect	oidc-usermodel-property-mapper	\N	67754b0a-38a9-458e-9c59-3f1fdcd2439b
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	email verified	openid-connect	oidc-usermodel-property-mapper	\N	67754b0a-38a9-458e-9c59-3f1fdcd2439b
06280786-34eb-43c2-8688-ec7271932182	address	openid-connect	oidc-address-mapper	\N	7031920c-9eb7-4389-86fb-f2cd3141f51d
34039361-c405-4100-8417-ecb2949c30b3	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	f4566753-b0d7-477b-9028-4fd25f418306
34a54e2f-f581-4c93-bf08-d654ac743714	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	f4566753-b0d7-477b-9028-4fd25f418306
26dbe9c4-6d0b-4969-bb80-053c39cd7b53	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc
ff94c740-4b06-4c28-95c3-a43def888cdf	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc
39c265a4-c7fd-4560-970e-635d32abaf2c	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	ffc4599b-53a6-41cb-8bb6-08b2aa6071cc
7e648b48-4b50-4341-bffe-f15cf3a3f9af	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	ac7bf87c-385e-41ec-8596-44c38dc6850b
c355e366-d830-4964-b897-eab6421953b7	upn	openid-connect	oidc-usermodel-property-mapper	\N	b058e660-4520-4503-8f2a-0e3cbac25da8
4d32caac-b718-4bf3-9541-1b1759392b31	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	b058e660-4520-4503-8f2a-0e3cbac25da8
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	locale	openid-connect	oidc-usermodel-attribute-mapper	864375cb-3edf-44ed-85b0-8fd316506d30	\N
e7eb5cbe-fb98-4334-bb2b-3b3089a931cc	docker-v2-allow-all-mapper	docker-v2	docker-v2-allow-all-mapper	fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	\N
0dad9538-bf8f-4770-8601-911e72be1a6b	demo-client-mapper	openid-connect	oidc-audience-mapper	\N	0e947f5d-fbe9-4310-ba4f-c050ecdd3a52
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
33df8532-0f8e-4eca-85ef-f7c2a50a1806	true	userinfo.token.claim
33df8532-0f8e-4eca-85ef-f7c2a50a1806	locale	user.attribute
33df8532-0f8e-4eca-85ef-f7c2a50a1806	true	id.token.claim
33df8532-0f8e-4eca-85ef-f7c2a50a1806	true	access.token.claim
33df8532-0f8e-4eca-85ef-f7c2a50a1806	locale	claim.name
33df8532-0f8e-4eca-85ef-f7c2a50a1806	String	jsonType.label
2ec897cc-0873-4923-8b6b-c50fa35d21e1	false	single
2ec897cc-0873-4923-8b6b-c50fa35d21e1	Basic	attribute.nameformat
2ec897cc-0873-4923-8b6b-c50fa35d21e1	Role	attribute.name
c5948a8c-5ac2-4949-bd39-418a6c1d5f9f	true	userinfo.token.claim
c5948a8c-5ac2-4949-bd39-418a6c1d5f9f	true	id.token.claim
c5948a8c-5ac2-4949-bd39-418a6c1d5f9f	true	access.token.claim
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	true	userinfo.token.claim
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	lastName	user.attribute
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	true	id.token.claim
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	true	access.token.claim
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	family_name	claim.name
a30a8de9-98bb-4cc8-abfa-7f59e8fde2e6	String	jsonType.label
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	true	userinfo.token.claim
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	firstName	user.attribute
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	true	id.token.claim
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	true	access.token.claim
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	given_name	claim.name
0a0dda3d-d63d-445f-afa7-1aa0c3c48679	String	jsonType.label
a584c389-4eaa-447b-8d97-ccfdc491553d	true	userinfo.token.claim
a584c389-4eaa-447b-8d97-ccfdc491553d	middleName	user.attribute
a584c389-4eaa-447b-8d97-ccfdc491553d	true	id.token.claim
a584c389-4eaa-447b-8d97-ccfdc491553d	true	access.token.claim
a584c389-4eaa-447b-8d97-ccfdc491553d	middle_name	claim.name
a584c389-4eaa-447b-8d97-ccfdc491553d	String	jsonType.label
b05fb1a0-de63-49be-b7b7-a49aa022bb70	true	userinfo.token.claim
b05fb1a0-de63-49be-b7b7-a49aa022bb70	nickname	user.attribute
b05fb1a0-de63-49be-b7b7-a49aa022bb70	true	id.token.claim
b05fb1a0-de63-49be-b7b7-a49aa022bb70	true	access.token.claim
b05fb1a0-de63-49be-b7b7-a49aa022bb70	nickname	claim.name
b05fb1a0-de63-49be-b7b7-a49aa022bb70	String	jsonType.label
79739665-e21e-412c-8e3a-bb3c9809980b	true	userinfo.token.claim
79739665-e21e-412c-8e3a-bb3c9809980b	username	user.attribute
79739665-e21e-412c-8e3a-bb3c9809980b	true	id.token.claim
79739665-e21e-412c-8e3a-bb3c9809980b	true	access.token.claim
79739665-e21e-412c-8e3a-bb3c9809980b	preferred_username	claim.name
79739665-e21e-412c-8e3a-bb3c9809980b	String	jsonType.label
a20a943f-14fd-4d1c-90b3-da329549fe43	true	userinfo.token.claim
a20a943f-14fd-4d1c-90b3-da329549fe43	profile	user.attribute
a20a943f-14fd-4d1c-90b3-da329549fe43	true	id.token.claim
a20a943f-14fd-4d1c-90b3-da329549fe43	true	access.token.claim
a20a943f-14fd-4d1c-90b3-da329549fe43	profile	claim.name
a20a943f-14fd-4d1c-90b3-da329549fe43	String	jsonType.label
8399b9e5-146d-46c6-9e9a-04bb65bce349	true	userinfo.token.claim
8399b9e5-146d-46c6-9e9a-04bb65bce349	picture	user.attribute
8399b9e5-146d-46c6-9e9a-04bb65bce349	true	id.token.claim
8399b9e5-146d-46c6-9e9a-04bb65bce349	true	access.token.claim
8399b9e5-146d-46c6-9e9a-04bb65bce349	picture	claim.name
8399b9e5-146d-46c6-9e9a-04bb65bce349	String	jsonType.label
1f04f149-b5a1-4e53-a5c9-afbb7f552170	true	userinfo.token.claim
1f04f149-b5a1-4e53-a5c9-afbb7f552170	website	user.attribute
1f04f149-b5a1-4e53-a5c9-afbb7f552170	true	id.token.claim
1f04f149-b5a1-4e53-a5c9-afbb7f552170	true	access.token.claim
1f04f149-b5a1-4e53-a5c9-afbb7f552170	website	claim.name
1f04f149-b5a1-4e53-a5c9-afbb7f552170	String	jsonType.label
e0d19512-090d-471e-8537-82405bc69bd7	true	userinfo.token.claim
e0d19512-090d-471e-8537-82405bc69bd7	gender	user.attribute
e0d19512-090d-471e-8537-82405bc69bd7	true	id.token.claim
e0d19512-090d-471e-8537-82405bc69bd7	true	access.token.claim
e0d19512-090d-471e-8537-82405bc69bd7	gender	claim.name
e0d19512-090d-471e-8537-82405bc69bd7	String	jsonType.label
899f29f9-73b5-4ac4-8504-df853888c382	true	userinfo.token.claim
899f29f9-73b5-4ac4-8504-df853888c382	birthdate	user.attribute
899f29f9-73b5-4ac4-8504-df853888c382	true	id.token.claim
899f29f9-73b5-4ac4-8504-df853888c382	true	access.token.claim
899f29f9-73b5-4ac4-8504-df853888c382	birthdate	claim.name
899f29f9-73b5-4ac4-8504-df853888c382	String	jsonType.label
41103857-e637-4856-801d-221c1e158a3e	true	userinfo.token.claim
41103857-e637-4856-801d-221c1e158a3e	zoneinfo	user.attribute
41103857-e637-4856-801d-221c1e158a3e	true	id.token.claim
41103857-e637-4856-801d-221c1e158a3e	true	access.token.claim
41103857-e637-4856-801d-221c1e158a3e	zoneinfo	claim.name
41103857-e637-4856-801d-221c1e158a3e	String	jsonType.label
44fe0133-3b68-4418-a00e-9f8217d90a77	true	userinfo.token.claim
44fe0133-3b68-4418-a00e-9f8217d90a77	locale	user.attribute
44fe0133-3b68-4418-a00e-9f8217d90a77	true	id.token.claim
44fe0133-3b68-4418-a00e-9f8217d90a77	true	access.token.claim
44fe0133-3b68-4418-a00e-9f8217d90a77	locale	claim.name
44fe0133-3b68-4418-a00e-9f8217d90a77	String	jsonType.label
193a2f41-b78b-4b27-95ef-aee1e5f055ff	true	userinfo.token.claim
193a2f41-b78b-4b27-95ef-aee1e5f055ff	updatedAt	user.attribute
193a2f41-b78b-4b27-95ef-aee1e5f055ff	true	id.token.claim
193a2f41-b78b-4b27-95ef-aee1e5f055ff	true	access.token.claim
193a2f41-b78b-4b27-95ef-aee1e5f055ff	updated_at	claim.name
193a2f41-b78b-4b27-95ef-aee1e5f055ff	String	jsonType.label
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	true	userinfo.token.claim
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	email	user.attribute
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	true	id.token.claim
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	true	access.token.claim
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	email	claim.name
d15dfa39-8ca7-46b8-b5c6-3c71b92e1f8f	String	jsonType.label
679aa3f4-8a10-4581-ba44-12fb09c6b39a	true	userinfo.token.claim
679aa3f4-8a10-4581-ba44-12fb09c6b39a	emailVerified	user.attribute
679aa3f4-8a10-4581-ba44-12fb09c6b39a	true	id.token.claim
679aa3f4-8a10-4581-ba44-12fb09c6b39a	true	access.token.claim
679aa3f4-8a10-4581-ba44-12fb09c6b39a	email_verified	claim.name
679aa3f4-8a10-4581-ba44-12fb09c6b39a	boolean	jsonType.label
973514cc-2f86-49d7-a6eb-53f6d828ce20	formatted	user.attribute.formatted
973514cc-2f86-49d7-a6eb-53f6d828ce20	country	user.attribute.country
973514cc-2f86-49d7-a6eb-53f6d828ce20	postal_code	user.attribute.postal_code
973514cc-2f86-49d7-a6eb-53f6d828ce20	true	userinfo.token.claim
973514cc-2f86-49d7-a6eb-53f6d828ce20	street	user.attribute.street
973514cc-2f86-49d7-a6eb-53f6d828ce20	true	id.token.claim
973514cc-2f86-49d7-a6eb-53f6d828ce20	region	user.attribute.region
973514cc-2f86-49d7-a6eb-53f6d828ce20	true	access.token.claim
973514cc-2f86-49d7-a6eb-53f6d828ce20	locality	user.attribute.locality
c2c5d853-8fe5-41c9-8453-7568ec4b3213	true	userinfo.token.claim
c2c5d853-8fe5-41c9-8453-7568ec4b3213	phoneNumber	user.attribute
c2c5d853-8fe5-41c9-8453-7568ec4b3213	true	id.token.claim
c2c5d853-8fe5-41c9-8453-7568ec4b3213	true	access.token.claim
c2c5d853-8fe5-41c9-8453-7568ec4b3213	phone_number	claim.name
c2c5d853-8fe5-41c9-8453-7568ec4b3213	String	jsonType.label
b1f6cfce-402f-438f-a082-2a03dccd7847	true	userinfo.token.claim
b1f6cfce-402f-438f-a082-2a03dccd7847	phoneNumberVerified	user.attribute
b1f6cfce-402f-438f-a082-2a03dccd7847	true	id.token.claim
b1f6cfce-402f-438f-a082-2a03dccd7847	true	access.token.claim
b1f6cfce-402f-438f-a082-2a03dccd7847	phone_number_verified	claim.name
b1f6cfce-402f-438f-a082-2a03dccd7847	boolean	jsonType.label
3f7a7abd-67f6-4139-80c1-2200bf06b8e2	true	multivalued
3f7a7abd-67f6-4139-80c1-2200bf06b8e2	foo	user.attribute
3f7a7abd-67f6-4139-80c1-2200bf06b8e2	true	access.token.claim
3f7a7abd-67f6-4139-80c1-2200bf06b8e2	realm_access.roles	claim.name
3f7a7abd-67f6-4139-80c1-2200bf06b8e2	String	jsonType.label
346514f0-95bd-4ab1-a77f-eca5ca2d253a	true	multivalued
346514f0-95bd-4ab1-a77f-eca5ca2d253a	foo	user.attribute
346514f0-95bd-4ab1-a77f-eca5ca2d253a	true	access.token.claim
346514f0-95bd-4ab1-a77f-eca5ca2d253a	resource_access.${client_id}.roles	claim.name
346514f0-95bd-4ab1-a77f-eca5ca2d253a	String	jsonType.label
617d85de-3838-456d-b2da-6ae1f3fd93e3	true	userinfo.token.claim
617d85de-3838-456d-b2da-6ae1f3fd93e3	username	user.attribute
617d85de-3838-456d-b2da-6ae1f3fd93e3	true	id.token.claim
617d85de-3838-456d-b2da-6ae1f3fd93e3	true	access.token.claim
617d85de-3838-456d-b2da-6ae1f3fd93e3	upn	claim.name
617d85de-3838-456d-b2da-6ae1f3fd93e3	String	jsonType.label
5069b46f-7a04-4a03-ab55-f2cbea898931	true	multivalued
5069b46f-7a04-4a03-ab55-f2cbea898931	foo	user.attribute
5069b46f-7a04-4a03-ab55-f2cbea898931	true	id.token.claim
5069b46f-7a04-4a03-ab55-f2cbea898931	true	access.token.claim
5069b46f-7a04-4a03-ab55-f2cbea898931	groups	claim.name
5069b46f-7a04-4a03-ab55-f2cbea898931	String	jsonType.label
d8fc54d1-40e1-4b84-ad33-5ac289d691e0	false	single
d8fc54d1-40e1-4b84-ad33-5ac289d691e0	Basic	attribute.nameformat
d8fc54d1-40e1-4b84-ad33-5ac289d691e0	Role	attribute.name
d3d4025a-3c30-4a50-b519-2b0d6f502548	true	userinfo.token.claim
d3d4025a-3c30-4a50-b519-2b0d6f502548	true	id.token.claim
d3d4025a-3c30-4a50-b519-2b0d6f502548	true	access.token.claim
9b91c18d-b477-400a-9ef0-6912cc1a42fd	true	userinfo.token.claim
9b91c18d-b477-400a-9ef0-6912cc1a42fd	lastName	user.attribute
9b91c18d-b477-400a-9ef0-6912cc1a42fd	true	id.token.claim
9b91c18d-b477-400a-9ef0-6912cc1a42fd	true	access.token.claim
9b91c18d-b477-400a-9ef0-6912cc1a42fd	family_name	claim.name
9b91c18d-b477-400a-9ef0-6912cc1a42fd	String	jsonType.label
dec28b68-100a-48f2-9c90-bbe49848a444	true	userinfo.token.claim
dec28b68-100a-48f2-9c90-bbe49848a444	firstName	user.attribute
dec28b68-100a-48f2-9c90-bbe49848a444	true	id.token.claim
dec28b68-100a-48f2-9c90-bbe49848a444	true	access.token.claim
dec28b68-100a-48f2-9c90-bbe49848a444	given_name	claim.name
dec28b68-100a-48f2-9c90-bbe49848a444	String	jsonType.label
cc90cc89-2468-44f3-a0f6-0b804321c3c4	true	userinfo.token.claim
cc90cc89-2468-44f3-a0f6-0b804321c3c4	middleName	user.attribute
cc90cc89-2468-44f3-a0f6-0b804321c3c4	true	id.token.claim
cc90cc89-2468-44f3-a0f6-0b804321c3c4	true	access.token.claim
cc90cc89-2468-44f3-a0f6-0b804321c3c4	middle_name	claim.name
cc90cc89-2468-44f3-a0f6-0b804321c3c4	String	jsonType.label
e3f2f18d-7483-4152-8e68-782dc568e761	true	userinfo.token.claim
e3f2f18d-7483-4152-8e68-782dc568e761	nickname	user.attribute
e3f2f18d-7483-4152-8e68-782dc568e761	true	id.token.claim
e3f2f18d-7483-4152-8e68-782dc568e761	true	access.token.claim
e3f2f18d-7483-4152-8e68-782dc568e761	nickname	claim.name
e3f2f18d-7483-4152-8e68-782dc568e761	String	jsonType.label
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	true	userinfo.token.claim
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	username	user.attribute
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	true	id.token.claim
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	true	access.token.claim
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	preferred_username	claim.name
61da0aa7-ba09-4e63-bb78-5aeaf36836dd	String	jsonType.label
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	true	userinfo.token.claim
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	profile	user.attribute
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	true	id.token.claim
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	true	access.token.claim
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	profile	claim.name
3f24d4a9-7f39-434d-afeb-b29bc75e17f2	String	jsonType.label
ee5ebec5-c241-4144-86c4-65fc8d516bd8	true	userinfo.token.claim
ee5ebec5-c241-4144-86c4-65fc8d516bd8	picture	user.attribute
ee5ebec5-c241-4144-86c4-65fc8d516bd8	true	id.token.claim
ee5ebec5-c241-4144-86c4-65fc8d516bd8	true	access.token.claim
ee5ebec5-c241-4144-86c4-65fc8d516bd8	picture	claim.name
ee5ebec5-c241-4144-86c4-65fc8d516bd8	String	jsonType.label
e8a7d270-585b-477e-a04a-c1cf51077a66	true	userinfo.token.claim
e8a7d270-585b-477e-a04a-c1cf51077a66	website	user.attribute
e8a7d270-585b-477e-a04a-c1cf51077a66	true	id.token.claim
e8a7d270-585b-477e-a04a-c1cf51077a66	true	access.token.claim
e8a7d270-585b-477e-a04a-c1cf51077a66	website	claim.name
e8a7d270-585b-477e-a04a-c1cf51077a66	String	jsonType.label
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	true	userinfo.token.claim
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	gender	user.attribute
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	true	id.token.claim
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	true	access.token.claim
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	gender	claim.name
b38d96ef-15d3-4d5a-b35f-71a5e20b4781	String	jsonType.label
eb035e76-805e-4029-a973-83276212d771	true	userinfo.token.claim
eb035e76-805e-4029-a973-83276212d771	birthdate	user.attribute
eb035e76-805e-4029-a973-83276212d771	true	id.token.claim
eb035e76-805e-4029-a973-83276212d771	true	access.token.claim
eb035e76-805e-4029-a973-83276212d771	birthdate	claim.name
eb035e76-805e-4029-a973-83276212d771	String	jsonType.label
2a5502f2-4ec1-4dbe-874d-f378fb733040	true	userinfo.token.claim
2a5502f2-4ec1-4dbe-874d-f378fb733040	zoneinfo	user.attribute
2a5502f2-4ec1-4dbe-874d-f378fb733040	true	id.token.claim
2a5502f2-4ec1-4dbe-874d-f378fb733040	true	access.token.claim
2a5502f2-4ec1-4dbe-874d-f378fb733040	zoneinfo	claim.name
2a5502f2-4ec1-4dbe-874d-f378fb733040	String	jsonType.label
77c7dd72-25ab-4448-ba88-24475e5c7047	true	userinfo.token.claim
77c7dd72-25ab-4448-ba88-24475e5c7047	locale	user.attribute
77c7dd72-25ab-4448-ba88-24475e5c7047	true	id.token.claim
77c7dd72-25ab-4448-ba88-24475e5c7047	true	access.token.claim
77c7dd72-25ab-4448-ba88-24475e5c7047	locale	claim.name
77c7dd72-25ab-4448-ba88-24475e5c7047	String	jsonType.label
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	true	userinfo.token.claim
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	updatedAt	user.attribute
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	true	id.token.claim
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	true	access.token.claim
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	updated_at	claim.name
5a0d4e7d-51dc-4014-9cc4-3d70768d797b	String	jsonType.label
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	true	userinfo.token.claim
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	email	user.attribute
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	true	id.token.claim
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	true	access.token.claim
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	email	claim.name
26dd588c-3c2d-4bf2-9f00-bd767b9b6c94	String	jsonType.label
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	true	userinfo.token.claim
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	emailVerified	user.attribute
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	true	id.token.claim
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	true	access.token.claim
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	email_verified	claim.name
b4ecdb00-3732-4a5c-ad2d-93790fd1ec11	boolean	jsonType.label
06280786-34eb-43c2-8688-ec7271932182	formatted	user.attribute.formatted
06280786-34eb-43c2-8688-ec7271932182	country	user.attribute.country
06280786-34eb-43c2-8688-ec7271932182	postal_code	user.attribute.postal_code
06280786-34eb-43c2-8688-ec7271932182	true	userinfo.token.claim
06280786-34eb-43c2-8688-ec7271932182	street	user.attribute.street
06280786-34eb-43c2-8688-ec7271932182	true	id.token.claim
06280786-34eb-43c2-8688-ec7271932182	region	user.attribute.region
06280786-34eb-43c2-8688-ec7271932182	true	access.token.claim
06280786-34eb-43c2-8688-ec7271932182	locality	user.attribute.locality
34039361-c405-4100-8417-ecb2949c30b3	true	userinfo.token.claim
34039361-c405-4100-8417-ecb2949c30b3	phoneNumber	user.attribute
34039361-c405-4100-8417-ecb2949c30b3	true	id.token.claim
34039361-c405-4100-8417-ecb2949c30b3	true	access.token.claim
34039361-c405-4100-8417-ecb2949c30b3	phone_number	claim.name
34039361-c405-4100-8417-ecb2949c30b3	String	jsonType.label
34a54e2f-f581-4c93-bf08-d654ac743714	true	userinfo.token.claim
34a54e2f-f581-4c93-bf08-d654ac743714	phoneNumberVerified	user.attribute
34a54e2f-f581-4c93-bf08-d654ac743714	true	id.token.claim
34a54e2f-f581-4c93-bf08-d654ac743714	true	access.token.claim
34a54e2f-f581-4c93-bf08-d654ac743714	phone_number_verified	claim.name
34a54e2f-f581-4c93-bf08-d654ac743714	boolean	jsonType.label
26dbe9c4-6d0b-4969-bb80-053c39cd7b53	true	multivalued
26dbe9c4-6d0b-4969-bb80-053c39cd7b53	foo	user.attribute
26dbe9c4-6d0b-4969-bb80-053c39cd7b53	true	access.token.claim
26dbe9c4-6d0b-4969-bb80-053c39cd7b53	realm_access.roles	claim.name
26dbe9c4-6d0b-4969-bb80-053c39cd7b53	String	jsonType.label
ff94c740-4b06-4c28-95c3-a43def888cdf	true	multivalued
ff94c740-4b06-4c28-95c3-a43def888cdf	foo	user.attribute
ff94c740-4b06-4c28-95c3-a43def888cdf	true	access.token.claim
ff94c740-4b06-4c28-95c3-a43def888cdf	resource_access.${client_id}.roles	claim.name
ff94c740-4b06-4c28-95c3-a43def888cdf	String	jsonType.label
c355e366-d830-4964-b897-eab6421953b7	true	userinfo.token.claim
c355e366-d830-4964-b897-eab6421953b7	username	user.attribute
c355e366-d830-4964-b897-eab6421953b7	true	id.token.claim
c355e366-d830-4964-b897-eab6421953b7	true	access.token.claim
c355e366-d830-4964-b897-eab6421953b7	upn	claim.name
c355e366-d830-4964-b897-eab6421953b7	String	jsonType.label
4d32caac-b718-4bf3-9541-1b1759392b31	true	multivalued
4d32caac-b718-4bf3-9541-1b1759392b31	foo	user.attribute
4d32caac-b718-4bf3-9541-1b1759392b31	true	id.token.claim
4d32caac-b718-4bf3-9541-1b1759392b31	true	access.token.claim
4d32caac-b718-4bf3-9541-1b1759392b31	groups	claim.name
4d32caac-b718-4bf3-9541-1b1759392b31	String	jsonType.label
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	true	userinfo.token.claim
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	locale	user.attribute
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	true	id.token.claim
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	true	access.token.claim
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	locale	claim.name
a03137b3-d703-4d7f-9dba-4f6cd6c7450c	String	jsonType.label
0dad9538-bf8f-4770-8601-911e72be1a6b	demo-client	included.client.audience
0dad9538-bf8f-4770-8601-911e72be1a6b	true	id.token.claim
0dad9538-bf8f-4770-8601-911e72be1a6b	true	access.token.claim
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me) FROM stdin;
master	60	300	60	\N	\N	\N	t	f	0	\N	master	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	e96afb04-c8e3-4d09-b74d-06fa364e582f	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	61cc22e4-b9c6-47e7-ac02-1ddbea8ee3c3	55ef2c02-8a13-4b07-a0ae-1819eec243fd	a731b298-68b4-439b-9c32-a797cd2b193c	6c18703e-0471-4e4c-9e82-9e7152f2fb57	c286ae1f-2b78-4f32-b61c-3cea420d921a	2592000	f	900	t	f	26906350-dd66-4523-a8c7-432e192eb2d4	0	f	0	0
demo-realm	60	300	300	\N	\N	\N	t	f	0	\N	demo-realm	0	\N	t	f	f	f	EXTERNAL	1800	36000	f	f	ca12f299-0359-4701-ae0f-5c90768b7b34	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	c3a1c48c-8f50-4c5b-a256-8b2b69cb934e	8ca230c1-0f87-4262-a1af-6655b83c2062	c0c6fff4-f801-437f-b154-c10f0800ba42	ac20009e-4fc7-4010-a67f-754a2802cb63	40813a36-c7e7-49df-8961-9e7394d0e2c6	2592000	f	900	t	f	551c47d5-b309-45a4-a32f-3363f22c421d	0	f	0	0
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_attribute (name, value, realm_id) FROM stdin;
_browser_header.contentSecurityPolicyReportOnly		master
_browser_header.xContentTypeOptions	nosniff	master
_browser_header.xRobotsTag	none	master
_browser_header.xFrameOptions	SAMEORIGIN	master
_browser_header.contentSecurityPolicy	frame-src 'self'; frame-ancestors 'self'; object-src 'none';	master
_browser_header.xXSSProtection	1; mode=block	master
_browser_header.strictTransportSecurity	max-age=31536000; includeSubDomains	master
bruteForceProtected	false	master
permanentLockout	false	master
maxFailureWaitSeconds	900	master
minimumQuickLoginWaitSeconds	60	master
waitIncrementSeconds	60	master
quickLoginCheckMilliSeconds	1000	master
maxDeltaTimeSeconds	43200	master
failureFactor	30	master
displayName	Keycloak	master
displayNameHtml	<div class="kc-logo-text"><span>Keycloak</span></div>	master
offlineSessionMaxLifespanEnabled	false	master
offlineSessionMaxLifespan	5184000	master
_browser_header.contentSecurityPolicyReportOnly		demo-realm
_browser_header.xContentTypeOptions	nosniff	demo-realm
_browser_header.xRobotsTag	none	demo-realm
_browser_header.xFrameOptions	SAMEORIGIN	demo-realm
_browser_header.contentSecurityPolicy	frame-src 'self'; frame-ancestors 'self'; object-src 'none';	demo-realm
_browser_header.xXSSProtection	1; mode=block	demo-realm
_browser_header.strictTransportSecurity	max-age=31536000; includeSubDomains	demo-realm
bruteForceProtected	false	demo-realm
permanentLockout	false	demo-realm
maxFailureWaitSeconds	900	demo-realm
minimumQuickLoginWaitSeconds	60	demo-realm
waitIncrementSeconds	60	demo-realm
quickLoginCheckMilliSeconds	1000	demo-realm
maxDeltaTimeSeconds	43200	demo-realm
failureFactor	30	demo-realm
offlineSessionMaxLifespanEnabled	false	demo-realm
offlineSessionMaxLifespan	5184000	demo-realm
actionTokenGeneratedByAdminLifespan	43200	demo-realm
actionTokenGeneratedByUserLifespan	300	demo-realm
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_default_roles; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_default_roles (realm_id, role_id) FROM stdin;
master	34c8ae53-e5dd-4a42-bda1-9fe88860caa2
master	8323e721-a4bd-496c-bdbc-39746fc7552e
demo-realm	3169f3f9-83ae-4cfd-8fa9-34b8b37d68a9
demo-realm	19320043-3c40-4762-a607-662c8a105cf8
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
master	jboss-logging
demo-realm	jboss-logging
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	master
password	password	t	t	demo-realm
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.redirect_uris (client_id, value) FROM stdin;
a831efff-56c4-4eb0-b6cb-d4816b326de8	/auth/realms/master/account/*
5705c8e6-4bc0-4531-9edc-773d8295af8f	/auth/admin/master/console/*
438afdec-0eca-4e17-89f1-8133076985b3	/auth/realms/demo-realm/account/*
864375cb-3edf-44ed-85b0-8fd316506d30	/auth/admin/demo-realm/console/*
fbe6b3eb-9c48-46d9-aac1-9bbb2948a84b	https://service1.lab.com/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
503fe747-069d-4643-a53d-3fec50cf41bd	VERIFY_EMAIL	Verify Email	master	t	f	VERIFY_EMAIL	50
4b1a8c7c-1d0b-4823-9932-238d5fb2d57c	UPDATE_PROFILE	Update Profile	master	t	f	UPDATE_PROFILE	40
922e810d-73c6-46af-b2b3-52bd0bb51b71	CONFIGURE_TOTP	Configure OTP	master	t	f	CONFIGURE_TOTP	10
380b676f-3da6-4777-9d8e-f25fc7b46261	UPDATE_PASSWORD	Update Password	master	t	f	UPDATE_PASSWORD	30
d52ebc96-7d4c-4bd1-949a-fdd625438f7a	terms_and_conditions	Terms and Conditions	master	f	f	terms_and_conditions	20
b9a6d12b-d05b-4d16-9e79-bb650bd8ffcc	VERIFY_EMAIL	Verify Email	demo-realm	t	f	VERIFY_EMAIL	50
97b17a0e-eb2e-4544-a091-ecb3f48927cb	UPDATE_PROFILE	Update Profile	demo-realm	t	f	UPDATE_PROFILE	40
41597b2d-7d3b-4702-af17-a23f18cd9c58	CONFIGURE_TOTP	Configure OTP	demo-realm	t	f	CONFIGURE_TOTP	10
890206f6-d9ce-4a51-9cb6-7a7e15e583c4	UPDATE_PASSWORD	Update Password	demo-realm	t	f	UPDATE_PASSWORD	30
1ff65b5b-f8f9-427b-9f10-7f99816f3688	terms_and_conditions	Terms and Conditions	demo-realm	f	f	terms_and_conditions	20
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode, decision_strategy) FROM stdin;
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_uris (resource_id, value) FROM stdin;
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_attribute (name, value, user_id, id) FROM stdin;
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
d1f07e02-268a-4b1c-b8a5-0c049149038b	\N	ace72697-17d8-444b-9ad4-2451da635b67	f	t	\N	\N	\N	master	admin	1693395503685	\N	0
b4d7c216-78b4-4dc3-ae02-c93277e5c02c	last@lab.com	last@lab.com	f	t	\N	First	Last	demo-realm	tester	1693396524160	\N	0
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_group_membership (group_id, user_id) FROM stdin;
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
ab5d210f-5caf-4449-aed3-502dd36e7ebe	d1f07e02-268a-4b1c-b8a5-0c049149038b
8323e721-a4bd-496c-bdbc-39746fc7552e	d1f07e02-268a-4b1c-b8a5-0c049149038b
34c8ae53-e5dd-4a42-bda1-9fe88860caa2	d1f07e02-268a-4b1c-b8a5-0c049149038b
d7e91971-22d9-4051-b421-6775f9ddcc3a	d1f07e02-268a-4b1c-b8a5-0c049149038b
fb175756-86a1-408c-89ce-c122f1be393f	d1f07e02-268a-4b1c-b8a5-0c049149038b
b5fe97e3-364e-4d57-8039-a29c8e950ab8	b4d7c216-78b4-4dc3-ae02-c93277e5c02c
1cbf3fee-dada-4fb5-b2c0-583fbc1ee8bf	b4d7c216-78b4-4dc3-ae02-c93277e5c02c
3169f3f9-83ae-4cfd-8fa9-34b8b37d68a9	b4d7c216-78b4-4dc3-ae02-c93277e5c02c
19320043-3c40-4762-a607-662c8a105cf8	b4d7c216-78b4-4dc3-ae02-c93277e5c02c
\.


--
-- Data for Name: user_session; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_session (id, auth_method, ip_address, last_session_refresh, login_username, realm_id, remember_me, started, user_id, user_session_state, broker_session_id, broker_user_id) FROM stdin;
\.


--
-- Data for Name: user_session_note; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_session_note (user_session, name, value) FROM stdin;
\.


--
-- Data for Name: username_login_failure; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.username_login_failure (realm_id, username, failed_login_not_before, last_failure, last_ip_failure, num_failures) FROM stdin;
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.web_origins (client_id, value) FROM stdin;
\.


--
-- Name: username_login_failure CONSTRAINT_17-2; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.username_login_failure
    ADD CONSTRAINT "CONSTRAINT_17-2" PRIMARY KEY (realm_id, username);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: client_user_session_note constr_cl_usr_ses_note; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT constr_cl_usr_ses_note PRIMARY KEY (client_session, name);


--
-- Name: client_default_roles constr_client_default_roles; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT constr_client_default_roles PRIMARY KEY (client_id, role_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: client_session_role constraint_5; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT constraint_5 PRIMARY KEY (client_session, role_id);


--
-- Name: user_session constraint_57; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT constraint_57 PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client_session_note constraint_5e; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT constraint_5e PRIMARY KEY (client_session, name);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: client_session constraint_8; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT constraint_8 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: client_session_auth_status constraint_auth_status_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT constraint_auth_status_pk PRIMARY KEY (client_session, authenticator);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: credential_attribute constraint_credential_attr; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT constraint_credential_attr PRIMARY KEY (id);


--
-- Name: client_session_prot_mapper constraint_cs_pmp_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT constraint_cs_pmp_pk PRIMARY KEY (client_session, protocol_mapper_id);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: fed_credential_attribute constraint_fed_credential_attr; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT constraint_fed_credential_attr PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: realm_default_roles constraint_realm_default_roles; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT constraint_realm_default_roles PRIMARY KEY (realm_id, role_id);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: resource_uris constraint_resour_uris_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT constraint_resour_uris_pk PRIMARY KEY (resource_id, value);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: user_session_note constraint_usn_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT constraint_usn_pk PRIMARY KEY (user_session, name);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: databasechangeloglock pk_databasechangeloglock; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT pk_databasechangeloglock PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client_default_roles uk_8aelwnibji49avxsrtuf6xjow; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT uk_8aelwnibji49avxsrtuf6xjow UNIQUE (role_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: realm_default_roles uk_h4wpd7w4hsoolni3h0sw7btje; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT uk_h4wpd7w4hsoolni3h0sw7btje UNIQUE (role_id);


--
-- Name: user_consent uk_jkuwuvd56ontgsuhogm8uewrt; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_jkuwuvd56ontgsuhogm8uewrt UNIQUE (client_id, client_storage_provider, external_client_id, user_id);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_def_roles_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_client_def_roles_client ON public.client_default_roles USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_client_session_session; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_client_session_session ON public.client_session USING btree (session_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_credential_attr_cred; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_credential_attr_cred ON public.credential_attribute USING btree (credential_id);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_fed_cred_attr_cred; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fed_cred_attr_cred ON public.fed_credential_attribute USING btree (credential_id);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_uss_createdon; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_offline_uss_createdon ON public.offline_user_session USING btree (created_on);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_def_roles_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_def_roles_realm ON public.realm_default_roles USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_us_sess_id_on_cl_sess; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_us_sess_id_on_cl_sess ON public.offline_client_session USING btree (user_session_id);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: client_session_auth_status auth_status_constraint; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT auth_status_constraint FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_session_note fk5edfb00ff51c2736; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT fk5edfb00ff51c2736 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: user_session_note fk5edfb00ff51d3472; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT fk5edfb00ff51d3472 FOREIGN KEY (user_session) REFERENCES public.user_session(id);


--
-- Name: client_session_role fk_11b7sgqw18i532811v7o2dv76; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT fk_11b7sgqw18i532811v7o2dv76 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session_prot_mapper fk_33a8sgqw18i532811v7o2dk89; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT fk_33a8sgqw18i532811v7o2dk89 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_default_roles fk_8aelwnibji49avxsrtuf6xjow; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_8aelwnibji49avxsrtuf6xjow FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session fk_b4ao2vcvat6ukau74wbwtfqo1; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT fk_b4ao2vcvat6ukau74wbwtfqo1 FOREIGN KEY (session_id) REFERENCES public.user_session(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_client fk_c_cli_scope_client; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_client FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_scope_client fk_c_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_role; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_user_session_note fk_cl_usr_ses_note; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT fk_cl_usr_ses_note FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: credential_attribute fk_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT fk_cred_attr FOREIGN KEY (credential_id) REFERENCES public.credential(id);


--
-- Name: realm_default_groups fk_def_groups_group; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_roles fk_evudb1ppw84oxfax2drs03icc; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_evudb1ppw84oxfax2drs03icc FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: fed_credential_attribute fk_fed_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT fk_fed_cred_attr FOREIGN KEY (credential_id) REFERENCES public.fed_user_credential(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: keycloak_group fk_group_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT fk_group_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: group_role_mapping fk_group_role_role; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_default_roles fk_h4wpd7w4hsoolni3h0sw7btje; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_h4wpd7w4hsoolni3h0sw7btje FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: keycloak_role fk_kjho5le2c0ral09fl8cm9wfw9; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_kjho5le2c0ral09fl8cm9wfw9 FOREIGN KEY (client) REFERENCES public.client(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_default_roles fk_nuilts7klwqw2h8m2b5joytky; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_nuilts7klwqw2h8m2b5joytky FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_p3rh9grku11kqfrs4fltt7rnq; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_p3rh9grku11kqfrs4fltt7rnq FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client fk_p56ctinxxb9gsk57fo49f9tac; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT fk_p56ctinxxb9gsk57fo49f9tac FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope fk_realm_cli_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT fk_realm_cli_scope FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: realm fk_traf444kk6qrkms7n56aiwq5y; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT fk_traf444kk6qrkms7n56aiwq5y FOREIGN KEY (master_admin_client) REFERENCES public.client(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

