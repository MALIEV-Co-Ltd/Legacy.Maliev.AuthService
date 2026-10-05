# Customer registration recovery links

The Web Instant Quotation fulfillment client calls `register/resolve` after an authorized registration conflict or unavailable response, using the persisted temporary password and customer ID. Recovery verifies that credential and may fill a null or zero customer link. An existing positive `DatabaseID` must match the requested customer ID; a different positive link returns the existing non-disclosing failure without changing identity properties or issuing sessions or action tokens.

This preserves same-customer lost-response recovery and the original identity-first signup's zero-ID intermediate state. It does not migrate original customer data, prove every historical UserManager operation, or authorize reassignment of an established customer account. The JSON DTO and HTTP failure shape remain unchanged.
