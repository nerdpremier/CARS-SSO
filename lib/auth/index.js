import { setSecurityHeaders } from '../response-utils.js';
import { handleAuthGet } from './get.js';
import { handleAuthPost } from './post.js';

export default async function authHandler(req, res) {
    setSecurityHeaders(res);

    if (req.method === 'GET') {
        return handleAuthGet(req, res);
    }
    if (req.method === 'POST') {
        return handleAuthPost(req, res);
    }
    return res.status(405).send();
}

