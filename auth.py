from config import AppConfig


def build_token_map(config: AppConfig) -> dict:
    token_map = {}
    for signer in config.signers:
        for token in signer.tokens:
            token_map[token] = {
                "role": "signer",
                "id": signer.id,
                "full_name": signer.full_name,
                "nickname": signer.nickname,
            }
    for token in config.viewer_tokens:
        token_map[token] = {"role": "viewer"}
    return token_map
