{#
 # Copyright (C) 2026 Maxime Wewer
 # SPDX-License-Identifier: BSD-2-Clause
 #}

<script>
    'use strict';

    $(document).ready(function () {
        mapDataToFormUI({ frm_settings: '/api/sso/settings/get' }).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('sso');
        });

        $('#save').click(function () {
            var $button = $(this).prop('disabled', true);
            saveFormToEndpoint('/api/sso/settings/set', 'frm_settings', function () {
                // Saving only stores the settings; writing vpn.conf is the apply step.
                ajaxCall('/api/sso/settings/reconfigure', {}, function (data) {
                    $button.prop('disabled', false);
                    $('#apply-result').text(data && data.status === 'ok'
                        ? '{{ lang._("Saved and applied.") }}'
                        : '{{ lang._("Saved, but writing vpn.conf failed - see the system log.") }}');
                });
            }, true, function () {
                $button.prop('disabled', false);
            });
        });
    });
</script>

<div class="content-box">
    <div style="padding: 1em;">
        {{ partial('layout_partials/base_form', ['fields': formSettings, 'id': 'frm_settings']) }}
        <button class="btn btn-primary" id="save" type="button">
            <b>{{ lang._('Save') }}</b> <i id="save_progress" class=""></i>
        </button>
        <span id="apply-result" class="text-muted" style="margin-left: 1em;"></span>
    </div>
</div>
