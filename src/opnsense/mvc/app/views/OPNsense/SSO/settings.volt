{#
 # Copyright (C) 2026 Maxime Wewer
 # SPDX-License-Identifier: BSD-2-Clause
 #}

<script>
    'use strict';

    $(document).ready(function () {
        // No updateServiceControlUI() here: os-sso runs no daemon of its own, and
        // asking for a service status that does not exist pops "Endpoint not found"
        // over the grid.
        $('#grid-profiles').UIBootgrid({
            search: '/api/sso/settings/searchProfile',
            get: '/api/sso/settings/getProfile/',
            set: '/api/sso/settings/setProfile/',
            add: '/api/sso/settings/addProfile/',
            del: '/api/sso/settings/delProfile/',
            toggle: '/api/sso/settings/toggleProfile/'
        });

        // Saving a row only stores it; writing vpn.conf is the apply step, and it is
        // the file every VPN connection attempt reads.
        $('#apply').click(function () {
            var $button = $(this).prop('disabled', true);
            ajaxCall('/api/sso/settings/reconfigure', {}, function (data) {
                $button.prop('disabled', false);
                $('#apply-result').text(data && data.status === 'ok'
                    ? '{{ lang._("Applied: vpn.conf rewritten.") }}'
                    : '{{ lang._("Writing vpn.conf failed - see the system log.") }}');
            });
        });
    });
</script>

<div class="content-box">
    <div style="padding: 1em;">
        <p class="text-muted">
            {{ lang._('One profile per OpenVPN server. Point the server at the script and name the
                       profile as its argument:') }}
            <code>auth-user-pass-verify "/usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh &lt;profile&gt;" via-file</code>.
            {{ lang._('A server that passes no name uses the first enabled profile.') }}
        </p>
    </div>

    <table id="grid-profiles" class="table table-condensed table-hover table-striped"
           data-editDialog="DialogProfile" data-editAlert="ProfileChangeMessage">
        <thead>
            <tr>
                <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                <th data-column-id="name" data-type="string" data-identifier="true">{{ lang._('Profile') }}</th>
                <th data-column-id="protocol" data-type="string">{{ lang._('Protocol') }}</th>
                <th data-column-id="provider" data-type="string">{{ lang._('Authentication server') }}</th>
                <th data-column-id="host" data-type="string">{{ lang._('Host') }}</th>
                <th data-column-id="timeout" data-type="string">{{ lang._('Timeout') }}</th>
                <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
        <tfoot>
            <tr>
                <td colspan="6"></td>
                <td>
                    <button data-action="add" type="button" class="btn btn-xs btn-primary">
                        <span class="fa fa-plus"></span>
                    </button>
                </td>
            </tr>
        </tfoot>
    </table>

    <div style="padding: 1em;">
        <button class="btn btn-primary" id="apply" type="button">
            <b>{{ lang._('Apply') }}</b>
        </button>
        <span id="apply-result" class="text-muted" style="margin-left: 1em;"></span>
    </div>
</div>

{{ partial('layout_partials/base_dialog', [
    'fields': formDialogProfile,
    'id': 'DialogProfile',
    'label': lang._('Edit web-auth profile')
]) }}
