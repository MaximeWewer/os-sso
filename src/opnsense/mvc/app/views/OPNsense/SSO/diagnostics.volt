{#
 # Copyright (C) 2026 Maxime Wewer
 # SPDX-License-Identifier: BSD-2-Clause
 #}

<script>
    'use strict';

    /**
     * Mostly read-only: the point is to answer, without reading syslog, does the IdP
     * actually respond, is it the one I configured, which URLs do I have to register
     * there, and who is signed in. The three buttons that do change something -- flush
     * the caches, end a session, end all of them -- are the ones an operator otherwise
     * has to do by disabling an account or waiting out a timeout.
     */
    $(document).ready(function () {

        function escapeHtml(value) {
            return $('<div/>').text(value === null || value === undefined ? '' : value).html();
        }

        function stamp(seconds) {
            if (!seconds) { return '-'; }
            return new Date(seconds * 1000).toLocaleString();
        }

        function urlRows(urls) {
            return Object.keys(urls).map(function (label) {
                return '<div class="small"><em>' + escapeHtml(label) + ':</em> <code>'
                    + escapeHtml(urls[label]) + '</code></div>';
            }).join('');
        }

        function flags(provider) {
            var out = [];
            if (provider.required_groups) {
                out.push('required groups: ' + escapeHtml(provider.required_groups));
            } else {
                out.push('<span class="text-warning">no required groups (any IdP account may log in)</span>');
            }
            if (provider.default_groups) { out.push('default groups: ' + escapeHtml(provider.default_groups)); }
            if (provider.create_users) { out.push('auto-creates users'); }
            if (provider.group_sync) { out.push('strict group sync'); }
            if (provider.deprovision) { out.push('deprovisions on refusal'); }
            if (provider.scim) { out.push('<span class="text-success">SCIM provisioning</span>'); }
            out.push(provider.session_lifetime > 0
                ? 'session lifetime: ' + provider.session_lifetime + 's'
                : '<span class="text-muted">no maximum session lifetime</span>');
            if (!provider.base_url_configured) {
                out.push('<span class="text-danger">Base URL not set (derived from the request Host)</span>');
            }
            return out.join(' &middot; ');
        }

        function renderProviders(data) {
            var $body = $('#providers-body').empty();
            if (!data.providers || data.providers.length === 0) {
                $body.append('<tr><td colspan="4"><em>{{ lang._("No SSO authentication server is configured yet.") }}</em></td></tr>');
                return;
            }
            data.providers.forEach(function (provider) {
                $body.append(
                    '<tr>'
                    + '<td><strong>' + escapeHtml(provider.name) + '</strong></td>'
                    + '<td>' + escapeHtml(provider.type.toUpperCase()) + '</td>'
                    + '<td>' + urlRows(provider.urls) + '<div class="small">' + flags(provider) + '</div></td>'
                    + '<td>'
                    + '<button class="btn btn-xs btn-default check-btn" data-provider="'
                    + escapeHtml(provider.name) + '">{{ lang._("Test") }}</button>'
                    + '<div class="check-result small" id="check-' + escapeHtml(provider.name).replace(/\W/g, '_') + '"></div>'
                    + '</td>'
                    + '</tr>'
                );
            });
        }

        function renderCheck($target, data) {
            if (data.status !== 'ok') {
                $target.html('<span class="text-danger">' + escapeHtml(data.message || 'failed') + '</span>');
                return;
            }
            var rows = Object.keys(data)
                .filter(function (key) { return key !== 'status' && data[key] !== '' && data[key] !== null; })
                .map(function (key) {
                    return '<div><em>' + escapeHtml(key) + ':</em> ' + escapeHtml(String(data[key])) + '</div>';
                });
            $target.html('<span class="text-success">{{ lang._("reachable") }}</span>' + rows.join(''));
        }

        function renderSessions(data) {
            var $body = $('#sessions-body').empty();
            if (!data.sessions || data.sessions.length === 0) {
                $body.append('<tr><td colspan="6"><em>{{ lang._("No SSO session is open.") }}</em></td></tr>');
                return;
            }
            data.sessions.forEach(function (session) {
                $body.append(
                    '<tr>'
                    + '<td>' + escapeHtml(session.username) + '</td>'
                    + '<td>' + escapeHtml(session.provider) + '</td>'
                    + '<td class="small">' + escapeHtml(session.subject) + '</td>'
                    + '<td>' + escapeHtml(stamp(session.started)) + '</td>'
                    + '<td>' + (session.expires_at ? escapeHtml(stamp(session.expires_at))
                        : '<span class="text-muted">{{ lang._("idle timeout only") }}</span>') + '</td>'
                    + '<td><button class="btn btn-xs btn-default end-session" data-id="'
                    + escapeHtml(session.id) + '" title="{{ lang._("End this session now.") }}">'
                    + '<i class="fa fa-sign-out"></i> {{ lang._("End") }}</button></td>'
                    + '</tr>'
                );
            });
        }

        function reload() {
            ajaxGet('/api/sso/diagnostics/providers', {}, renderProviders);
            ajaxGet('/api/sso/diagnostics/sessions', {}, renderSessions);
        }

        $(document).on('click', '.check-btn', function () {
            var provider = $(this).data('provider');
            var $target = $('#check-' + String(provider).replace(/\W/g, '_'));
            $target.html('<i class="fa fa-spinner fa-spin"></i>');
            ajaxGet('/api/sso/diagnostics/check/' + encodeURIComponent(provider), {}, function (data) {
                renderCheck($target, data || {});
            });
        });

        // Ending a session is the one destructive thing on this page, so it asks first
        // and then reloads the list rather than leaving a row that no longer exists.
        $(document).on('click', '.end-session', function () {
            var id = $(this).data('id');
            if (!id || !confirm('{{ lang._("End this SSO session? The user will have to sign in again.") }}')) {
                return;
            }
            ajaxCall('/api/sso/diagnostics/endSession/' + encodeURIComponent(id), {}, function () {
                reload();
            });
        });

        $('#end-all-sessions').click(function () {
            if (!confirm('{{ lang._("End every open SSO session, including your own if you signed in through SSO?") }}')) {
                return;
            }
            var $button = $(this).prop('disabled', true);
            ajaxCall('/api/sso/diagnostics/endAllSessions', {}, function (data) {
                $button.prop('disabled', false);
                $('#sessions-result').text(data && data.status === 'ok'
                    ? '{{ lang._("Ended") }} ' + data.ended + ' {{ lang._("session(s).") }}'
                    : '{{ lang._("Failed.") }}');
                reload();
            });
        });

        $('#flush-caches').click(function () {
            var $button = $(this).prop('disabled', true);
            ajaxCall('/api/sso/diagnostics/flushCaches', {}, function (data) {
                $button.prop('disabled', false);
                $('#flush-result').text(data && data.status === 'ok'
                    ? '{{ lang._("Dropped") }} ' + data.removed + ' {{ lang._("cached file(s).") }}'
                    : '{{ lang._("Failed.") }}');
            });
        });

        $('#reload').click(reload);
        reload();
    });
</script>

<style>
    /* IdP endpoints and JWKS URLs are longer than any column can be; let them wrap
       rather than stretch the page sideways. */
    #providers-body code, #providers-body .check-result { word-break: break-all; }
    #providers-body .check-result { max-width: 34em; }
</style>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="content-box-main">
        <div style="padding: 1em;">
            <button class="btn btn-primary" id="reload">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
            <button class="btn btn-default" id="flush-caches"
                    title="{{ lang._('Drop the cached discovery documents, JWKS, SAML metadata and icons so the next login refetches them.') }}">
                <i class="fa fa-trash"></i> {{ lang._('Flush caches') }}
            </button>
            <span id="flush-result" class="text-muted" style="margin-left: 1em;"></span>
        </div>

        <h2 style="padding-left: 0.6em;">{{ lang._('Providers') }}</h2>
        <div class="table-responsive">
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>{{ lang._('Name') }}</th>
                    <th>{{ lang._('Type') }}</th>
                    <th>{{ lang._('URLs to register at the IdP, and policy') }}</th>
                    <th>{{ lang._('Connectivity') }}</th>
                </tr>
            </thead>
            <tbody id="providers-body"></tbody>
        </table>
        </div>

        <h2 style="padding-left: 0.6em;">
            {{ lang._('Open SSO sessions') }}
            <button class="btn btn-default btn-xs" id="end-all-sessions" style="margin-left: 0.8em;"
                    title="{{ lang._('End every session os-sso opened.') }}">
                <i class="fa fa-sign-out"></i> {{ lang._('End all') }}
            </button>
            <span id="sessions-result" class="text-muted small" style="margin-left: 0.6em;"></span>
        </h2>
        <div class="table-responsive">
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>{{ lang._('User') }}</th>
                    <th>{{ lang._('Provider') }}</th>
                    <th>{{ lang._('IdP subject') }}</th>
                    <th>{{ lang._('Signed in') }}</th>
                    <th>{{ lang._('Expires') }}</th>
                    <th></th>
                </tr>
            </thead>
            <tbody id="sessions-body"></tbody>
        </table>
        </div>
    </div>
</div>
