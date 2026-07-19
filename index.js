/**
 * WebSocket Server — Massoko
 *
 * Key invariants:
 * 1. Every `receive_message` event MUST contain `signal_message_type`.
 *    It is extracted from the ciphertext "type:base64" prefix as a
 *    last-resort fallback if the PHP API omits it.
 * 2. `encrypted_content` is forwarded verbatim — never trimmed or re-encoded.
 * 3. Outgoing messages are persisted via the PHP API before broadcasting.
 * 4. On reconnect the client's pending_device_messages queue is delivered.
 */
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const PHP_API_URL = process.env.PHP_API_URL;

const onlineUsers = new Map();


// ─── Auth Middleware ──────────────────────────────────────────────────────────

io.use((socket, next) => {
  let token = socket.handshake.auth.token;
  if (!token) return next(new Error('Unauthorized: No token provided'));
  if (token.startsWith('Bearer ')) token = token.slice(7);
  try {
    socket.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch {
    next(new Error('Unauthorized: Invalid token'));
  }
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Extract the embedded Signal type from a "type:base64" prefixed ciphertext.
 * Returns the type integer (1, 2, or 3) or null if not found.
 */
function extractSignalType(content) {
  if (typeof content !== 'string') return null;
  const colonIdx = content.indexOf(':');
  if (colonIdx > 0 && colonIdx <= 2) {
    const parsed = parseInt(content.substring(0, colonIdx), 10);
    if (!isNaN(parsed) && (parsed === 1 || parsed === 2 || parsed === 3)) {
      return parsed;
    }
  }
  return null;
}

/**
 * Normalize the PHP API response into a guaranteed-safe socket event payload.
 * Ensures signal_message_type is NEVER missing.
 */
function normalizeMessage(phpResponse, fallbackSignalType) {
  const data = phpResponse || {};

  // Prefer the server's returned signal_message_type, fall back to the
  // value embedded in the ciphertext prefix, then to the caller-supplied
  // fallback (from the original socket event).
  const embeddedType = extractSignalType(
    data.encrypted_content || data.content || ''
  );

  const signalType =
    data.signal_message_type != null
      ? parseInt(data.signal_message_type, 10)
      : embeddedType != null
      ? embeddedType
      : fallbackSignalType != null
      ? parseInt(fallbackSignalType, 10)
      : 3; // last-resort default (PreKeyWhisperMessage)

  return {
    id:                   data.id,
    conversation_id:      data.conversation_id,
    sender_id:            data.sender_id,
    // Always use the field the frontend decrypts: encrypted_content.
    // The PHP API may return it as `encrypted_content` or `content`.
    encrypted_content:    data.encrypted_content ?? data.content,
    signal_message_type:  signalType,
    message_type:         data.type ?? data.message_type ?? 'text',
    sent_at:              data.sent_at,
    reply_to_message_id:  data.reply_to_message_id ?? null,
    attachment:           data.attachment ?? null,
  };
}

// ─── Deliver pending offline messages to a newly connected device ─────────────

async function deliverPendingMessages(socket) {
  try {
    const userId = socket.user.id || socket.user.user_id;
    const deviceId = socket.handshake.auth.device_id || 1;
    const response = await axios.get(
      `${PHP_API_URL}/messages/pending`,
      {
        params: { device_id: deviceId },
        headers: { Authorization: `Bearer ${socket.handshake.auth.token}` },
      }
    );

    const pending = response.data?.data?.messages || [];
    if (pending.length === 0) return;

    console.log(`[WS] Delivering ${pending.length} pending messages to user ${userId}`);

    for (const msg of pending) {
      socket.emit('receive_message', normalizeMessage(msg, msg.signal_message_type));
    }

    // Mark all pending as delivered
    await axios.post(
      `${PHP_API_URL}/messages/delivered`,
      { device_id: deviceId },
      { headers: { Authorization: `Bearer ${socket.handshake.auth.token}` } }
    );
  } catch (err) {
    // Non-fatal — client will re-fetch on next open
    console.warn('[WS] Failed to deliver pending messages:', err?.message);
  }
}

// ─── Socket Connection ────────────────────────────────────────────────────────

io.on('connection', async (socket) => {
  const userId = socket.user.id || socket.user.user_id;
  const personalRoom = `user_${userId}`;
  socket.join(personalRoom);

  const userIdStr = String(userId);
  console.log(`[WS] Connection attempt: User ${userIdStr} connected on socket ${socket.id}`);
  if (!onlineUsers.has(userIdStr)) {
    onlineUsers.set(userIdStr, new Set());
    console.log(`[WS] Broadcaster: User ${userIdStr} is now ONLINE. Emitting user_status 'online'.`);
    io.emit('user_status', { user_id: userIdStr, status: 'online' });
  } else {
    console.log(`[WS] User ${userIdStr} already has active connections. Current count: ${onlineUsers.get(userIdStr).size}`);
  }
  onlineUsers.get(userIdStr).add(socket.id);

  console.log(`[WS] User ${userId} connected`);

  // Deliver any queued offline messages immediately on connect
  await deliverPendingMessages(socket);

  // ── Join Conversation ─────────────────────────────────────────────────────

  socket.on('join_conversation', (conversationId) => {
    socket.join(`conversation_${conversationId}`);
  });

  socket.on('leave_conversation', (conversationId) => {
    socket.leave(`conversation_${conversationId}`);
  });

  // ── Send Message ──────────────────────────────────────────────────────────

  socket.on('send_message', async (data) => {
    const {
      conversation_id,
      content,
      message_type,
      signal_message_type,
      reply_to_message_id,
      attachment,
    } = data;

    // Validate signal_message_type before sending to PHP
    const resolvedSignalType =
      signal_message_type != null
        ? parseInt(signal_message_type, 10)
        : extractSignalType(content) ?? 3;

    if (isNaN(resolvedSignalType)) {
      console.error('[WS] send_message: invalid signal_message_type', signal_message_type);
      socket.emit('error_message', { message: 'Invalid signal_message_type' });
      return;
    }

    try {
      const response = await axios.post(
        `${PHP_API_URL}/messages`,
        {
          conversation_id,
          content,
          type:                 message_type || 'text',
          signal_message_type:  resolvedSignalType,
          reply_to_message_id:  reply_to_message_id || null,
          attachment:           attachment || null,
        },
        {
          headers: { Authorization: `Bearer ${socket.handshake.auth.token}` },
        }
      );

      const normalized = normalizeMessage(response.data, resolvedSignalType);
      io.to(`conversation_${conversation_id}`).emit('receive_message', normalized);

      // Emit to each participant's personal room
      const participantIds = response.data.participant_ids || [];
      participantIds.forEach(pId => {
        io.to(`user_${pId}`).emit('receive_message', normalized);
      });
    } catch (error) {
      console.error('[WS] send_message error:', error?.response?.data || error?.message);
      socket.emit('error_message', { message: 'Failed to send message' });
    }
  });

  // ── Read Receipts ─────────────────────────────────────────────────────────

  socket.on('mark_as_read', async ({ conversation_id }) => {
    try {
      const deviceId = socket.handshake.auth.device_id || 1;
      await axios.post(
        `${PHP_API_URL}/messages/read`,
        { conversation_id, device_id: deviceId },
        { headers: { Authorization: `Bearer ${socket.handshake.auth.token}` } }
      );

      io.to(`conversation_${conversation_id}`).emit('messages_read', {
        conversation_id,
        user_id: userId,
      });
    } catch {
      // Silently ignore — not critical path
    }
  });

  // ── Delete Message ────────────────────────────────────────────────────────

  socket.on('delete_message', async ({ message_id }) => {
    try {
      const response = await axios.post(
        `${PHP_API_URL}/messages/${message_id}/delete-everyone`,
        {},
        { headers: { Authorization: `Bearer ${socket.handshake.auth.token}` } }
      );

      if (response.data && response.data.success) {
        const responseData = response.data || {};
        const conversation_id = responseData.conversation_id;
        const participantIds = responseData.participant_ids || [];
        const payload = {
          message_id: message_id,
          conversation_id: conversation_id,
          deleted_by: userId,
        };

        // Emit to each participant's personal room
        participantIds.forEach((pId) => {
          io.to(`user_${pId}`).emit('message_deleted', payload);
        });
      }
    } catch (error) {
      console.error('[WS] delete_message error:', error?.response?.data || error?.message);
    }
  });

  // ── Edit Message ──────────────────────────────────────────────────────────

  socket.on('edit_message', async ({ message_id, new_content }) => {
    try {
      const response = await axios.post(
        `${PHP_API_URL}/messages/${message_id}/edit`,
        { content: new_content },
        { headers: { Authorization: `Bearer ${socket.handshake.auth.token}` } }
      );

      if (response.data && response.data.success) {
        const responseData = response.data || {};
        const conversation_id = responseData.conversation_id;
        const participantIds = responseData.participant_ids || [];
        const payload = {
          message_id: message_id,
          conversation_id: conversation_id,
          new_content: new_content,
          sender_id: userId,
        };

        // Emit to each participant's personal room
        participantIds.forEach((pId) => {
          io.to(`user_${pId}`).emit('message_edited', payload);
        });
      }
    } catch (error) {
      console.error('[WS] edit_message error:', error?.response?.data || error?.message);
    }
  });

  // ── Message Reactions ─────────────────────────────────────────────────────

  socket.on('message_reaction', (data) => {
    socket.to(`conversation_${data.conversation_id}`).emit('message_reaction', data);
  });

  // ── Typing Indicators ─────────────────────────────────────────────────────

  socket.typingTimers = new Map();

  socket.on('typing_start', ({ conversation_id }) => {
    const room = `conversation_${conversation_id}`;
    socket.to(room).emit('user_typing', { conversation_id, user_id: userId });

    if (socket.typingTimers.has(conversation_id)) {
      clearTimeout(socket.typingTimers.get(conversation_id));
    }

    const t = setTimeout(() => {
      socket.to(room).emit('user_stop_typing', { conversation_id, user_id: userId });
      socket.typingTimers.delete(conversation_id);
    }, 2500);

    socket.typingTimers.set(conversation_id, t);
  });

  socket.on('typing_stop', ({ conversation_id }) => {
    const room = `conversation_${conversation_id}`;
    if (socket.typingTimers.has(conversation_id)) {
      clearTimeout(socket.typingTimers.get(conversation_id));
      socket.typingTimers.delete(conversation_id);
    }
    socket.to(room).emit('user_stop_typing', { conversation_id, user_id: userId });
  });

  // ── Disconnect ────────────────────────────────────────────────────────────

  socket.on('disconnect', () => {
    console.log(`[WS] User ${userId} disconnected from socket ${socket.id}`);
    socket.typingTimers.forEach((t) => clearTimeout(t));
    socket.typingTimers.clear();

    const userIdStr = String(userId);
    const userSockets = onlineUsers.get(userIdStr);
    if (userSockets) {
      userSockets.delete(socket.id);
      console.log(`[WS] Removed socket connection ${socket.id} for user ${userIdStr}. Remaining connection count: ${userSockets.size}`);
      if (userSockets.size === 0) {
        onlineUsers.delete(userIdStr);
        console.log(`[WS] Broadcaster: User ${userIdStr} is now OFFLINE. Emitting user_status 'offline'.`);
        io.emit('user_status', { user_id: userIdStr, status: 'offline' });
      }
    }
  });

  // ── Get User Status ────────────────────────────────────────────────────────

  socket.on('get_user_status', ({ user_id }) => {
    const targetIdStr = String(user_id);
    const isOnline = onlineUsers.has(targetIdStr);
    console.log(`[WS] get_user_status query: is target ${targetIdStr} online? ${isOnline}`);
    socket.emit('user_status', { user_id: targetIdStr, status: isOnline ? 'online' : 'offline' });
  });
});

server.listen(PORT, () => {
  console.log(`[WS] WebSocket server running on port ${PORT}`);
  console.log(`[WS] PHP API: ${PHP_API_URL}`);
});
