// Upstream ARL default web credentials (admin / arlpass), retained for
// compatibility with the third-party image. Local, isolated use only: this runs
// once on a fresh arl-db volume. Change it before exposing ARL beyond localhost.
// Provenance and license: see THIRD_PARTY_NOTICES.md.
db.user.drop()
db.user.insert({ username: 'admin', password: hex_md5('arlsalt!@#' + 'arlpass') })
