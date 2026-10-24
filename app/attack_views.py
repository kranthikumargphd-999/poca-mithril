"""
Attack Scenario Testing Views for Phase 1 Validation
"""

import json
import hashlib
import math
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db import transaction
from .models import Users, PoCAProof, Agent, AttackLog, AgentReputation, GovernanceContract


# ============ ATTACK DETECTOR CLASS ============
class AttackDetector:
    """Detects and handles various attack scenarios"""
    
    ATTACK_TAMPERING = 'tampering'
    ATTACK_REPLAY = 'replay'
    ATTACK_UNAUTHORIZED = 'unauthorized'
    ATTACK_MODEL_SUBSTITUTION = 'model_substitution'
    ATTACK_REVOCATION = 'revocation'
    
    SEVERITY = {
        ATTACK_TAMPERING: 'critical',
        ATTACK_REPLAY: 'medium',
        ATTACK_UNAUTHORIZED: 'high',
        ATTACK_MODEL_SUBSTITUTION: 'critical',
        ATTACK_REVOCATION: 'high',
    }
    
    @classmethod
    def detect_response_tampering(cls, proof, expected_response_hash):
        """Scenario 2: Response Tampering Detection"""
        try:
            actual_hash = hashlib.sha256(proof.ai_response.encode()).hexdigest()
            
            if actual_hash != expected_response_hash:
                cls._log_attack(
                    attack_type=cls.ATTACK_TAMPERING,
                    severity=cls.SEVERITY[cls.ATTACK_TAMPERING],
                    proof_id=proof.proof_id,
                    agent_id=proof.agent.agent_id,
                    description=f"Response tampering detected on {proof.proof_id}",
                    details={
                        'expected_hash': expected_response_hash[:20] + '...',
                        'actual_hash': actual_hash[:20] + '...',
                    }
                )
                return True, "Response tampering detected - proof rejected"
            
            return False, "Response integrity verified"
            
        except Exception as e:
            return False, f"Tampering check failed: {str(e)}"
    
    @classmethod
    def detect_replay_attack(cls, proof_id, nonce, timestamp):
        """Scenario 3: Replay Attack Detection"""
        try:
            existing_proof = PoCAProof.objects.filter(proof_id=proof_id).first()
            
            if existing_proof:
                cls._log_attack(
                    attack_type=cls.ATTACK_REPLAY,
                    severity=cls.SEVERITY[cls.ATTACK_REPLAY],
                    proof_id=proof_id,
                    description=f"Replay attack detected for {proof_id}",
                    details={
                        'existing_created_at': existing_proof.created_at.isoformat(),
                        'nonce': nonce,
                    }
                )
                return True, "Replay attack detected - duplicate proof rejected"
            
            return False, "Fresh proof - accepted"
            
        except Exception as e:
            return False, f"Replay check failed: {str(e)}"
    
    @classmethod
    def detect_unauthorized_agent(cls, agent_did, public_key):
        """Scenario 4: Unauthorized Agent Detection"""
        try:
            agent = Agent.objects.filter(did=agent_did, status='active').first()
            
            if agent:
                return False, agent, "Authorized agent"
            
            agent = Agent.objects.filter(did=agent_did).first()
            if agent and agent.status == 'inactive':
                return True, None, "Agent is inactive"
            
            cls._log_attack(
                attack_type=cls.ATTACK_UNAUTHORIZED,
                severity=cls.SEVERITY[cls.ATTACK_UNAUTHORIZED],
                description=f"Unauthorized agent attempt: {agent_did}",
                details={'public_key': public_key[:30] + '...' if public_key else None}
            )
            return True, None, "Unauthorized agent - DID not registered"
            
        except Exception as e:
            return False, None, f"Authorization check failed: {str(e)}"
    
    @classmethod
    def detect_model_substitution(cls, agent, response_text, expected_behavior_pattern=None):
        """Scenario 5: Model Substitution Detection"""
        try:
            anomalies = []
            entropy_score = cls._calculate_entropy(response_text)
            
            if entropy_score > 7.5 or entropy_score < 3.0:
                anomalies.append({
                    'type': 'entropy_deviation',
                    'message': f"Entropy deviation: {entropy_score:.2f}",
                    'severity': 'high'
                })
            
            unusual_patterns = cls._detect_unusual_patterns(response_text)
            if unusual_patterns:
                anomalies.append({
                    'type': 'unusual_patterns',
                    'message': f"Unusual patterns: {', '.join(unusual_patterns)}",
                    'severity': 'medium'
                })
            
            if anomalies:
                cls._log_attack(
                    attack_type=cls.ATTACK_MODEL_SUBSTITUTION,
                    severity=cls.SEVERITY[cls.ATTACK_MODEL_SUBSTITUTION],
                    agent_id=agent.agent_id,
                    description=f"Model substitution detected for {agent.name}",
                    details={'anomalies': anomalies, 'entropy_score': entropy_score}
                )
                return True, "Abnormal behavior detected - agent flagged"
            
            return False, "Normal behavior confirmed"
            
        except Exception as e:
            return False, f"Model behavior check failed: {str(e)}"
    
    @classmethod
    def check_governance_revocation(cls, agent):
        """Scenario 6: Revocation Check"""
        try:
            governance = GovernanceContract.objects.filter(agent=agent).first()
            
            if governance and governance.is_revoked:
                cls._log_attack(
                    attack_type=cls.ATTACK_REVOCATION,
                    severity=cls.SEVERITY[cls.ATTACK_REVOCATION],
                    agent_id=agent.agent_id,
                    description=f"Revoked agent attempted communication: {agent.agent_id}",
                    details={'revoked_at': governance.revoked_at.isoformat() if governance.revoked_at else None}
                )
                return False, "Agent is revoked - communication blocked"
            
            return True, "Agent is authorized"
            
        except Exception as e:
            return False, f"Governance check failed: {str(e)}"
    
    @classmethod
    def _log_attack(cls, attack_type, severity, proof_id=None, agent_id=None, 
                    user_id=None, description="", details=None):
        """Log an attack attempt"""
        try:
            with transaction.atomic():
                log = AttackLog(
                    attack_type=attack_type,
                    severity=severity,
                    proof_id=proof_id,
                    agent_id=agent_id,
                    user_id=user_id,
                    description=description,
                    details=details or {},
                )
                log.save()
                return log
        except Exception as e:
            print(f"Failed to log attack: {e}")
            return None
    
    @classmethod
    def _calculate_entropy(cls, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0
        length = len(text)
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return min(entropy * 1.2, 10)
    
    @classmethod
    def _detect_unusual_patterns(cls, text):
        """Detect unusual patterns in text"""
        unusual = []
        
        if len(set(text.split())) < 10:
            unusual.append("repetitive_content")
        
        special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
        if special_count / max(len(text), 1) > 0.3:
            unusual.append("excessive_special_chars")
        
        try:
            text.encode('ascii')
        except UnicodeEncodeError:
            unusual.append("unicode_encoding_issue")
        
        return unusual


# ============ VIEW FUNCTIONS ============

@csrf_exempt
def test_attack_scenario(request, scenario_id):
    """
    Execute a specific attack scenario and return results
    """
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    if user.role != 'admin':
        return JsonResponse({'success': False, 'message': 'Admin access required'})
    
    try:
        data = json.loads(request.body) if request.body else {}
        result = {}
        
        if scenario_id == 1:
            result = execute_scenario_1_normal(data)
        elif scenario_id == 2:
            result = execute_scenario_2_tampering(data)
        elif scenario_id == 3:
            result = execute_scenario_3_replay(data)
        elif scenario_id == 4:
            result = execute_scenario_4_unauthorized(data)
        elif scenario_id == 5:
            result = execute_scenario_5_model_substitution(data)
        elif scenario_id == 6:
            result = execute_scenario_6_revocation(data)
        else:
            return JsonResponse({'success': False, 'message': 'Invalid scenario ID'})
        
        logs = AttackLog.objects.all().order_by('-detected_at')[:10]
        log_data = []
        for log in logs:
            log_data.append({
                'id': log.id,
                'attack_type': log.get_attack_type_display(),
                'severity': log.get_severity_display(),
                'proof_id': log.proof_id,
                'agent_id': log.agent_id,
                'description': log.description,
                'detected_at': log.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_resolved': log.is_resolved,
            })
        
        return JsonResponse({
            'success': True,
            'attack_result': result,
            'logs': log_data,
            'message': f"Attack scenario {scenario_id} executed"
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


def execute_scenario_1_normal(data):
    """Scenario 1: Normal Flow"""
    return {
        'scenario': 'Normal Flow',
        'status': 'success',
        'message': '✅ Normal operation - no attack detected',
        'attack_detected': False,
        'timestamp': timezone.now().isoformat()
    }


def execute_scenario_2_tampering(data):
    """Scenario 2: Response Tampering Attack"""
    proof_id = data.get('proof_id')
    if not proof_id:
        return {'error': 'Proof ID required'}
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id)
        original_response = proof.ai_response
        original_hash = hashlib.sha256(original_response.encode()).hexdigest()
        
        detected, message = AttackDetector.detect_response_tampering(proof, original_hash)
        
        return {
            'scenario': 'Response Tampering Attack',
            'status': 'attack_detected' if detected else 'failed',
            'message': message,
            'attack_detected': detected,
            'proof_id': proof_id,
            'original_hash': original_hash[:20] + '...',
            'timestamp': timezone.now().isoformat()
        }
        
    except PoCAProof.DoesNotExist:
        return {'error': 'Proof not found'}
    except Exception as e:
        return {'error': str(e)}


def execute_scenario_3_replay(data):
    """Scenario 3: Replay Attack"""
    proof_id = data.get('proof_id')
    if not proof_id:
        return {'error': 'Proof ID required'}
    
    try:
        proof = PoCAProof.objects.get(proof_id=proof_id)
        
        detected, message = AttackDetector.detect_replay_attack(
            proof_id=proof_id,
            nonce=f"replay_nonce_{int(timezone.now().timestamp())}",
            timestamp=timezone.now()
        )
        
        return {
            'scenario': 'Replay Attack',
            'status': 'attack_detected' if detected else 'failed',
            'message': message,
            'attack_detected': detected,
            'proof_id': proof_id,
            'created_at': proof.created_at.isoformat(),
            'timestamp': timezone.now().isoformat()
        }
        
    except PoCAProof.DoesNotExist:
        return {'error': 'Proof not found'}
    except Exception as e:
        return {'error': str(e)}


def execute_scenario_4_unauthorized(data):
    """Scenario 4: Unauthorized Agent Attack"""
    fake_did = data.get('fake_did', f"did:secureai:fake_{int(timezone.now().timestamp())}")
    fake_public_key = data.get('fake_public_key', 'fake_public_key_attack_12345')
    
    detected, agent, message = AttackDetector.detect_unauthorized_agent(
        agent_did=fake_did,
        public_key=fake_public_key
    )
    
    return {
        'scenario': 'Unauthorized Agent Attack',
        'status': 'attack_detected' if not detected else 'failed',
        'message': message,
        'attack_detected': not detected,
        'fake_did': fake_did,
        'fake_public_key': fake_public_key[:30] + '...',
        'timestamp': timezone.now().isoformat()
    }


def execute_scenario_5_model_substitution(data):
    """Scenario 5: Model Substitution Attack"""
    agent_id = data.get('agent_id')
    if not agent_id:
        return {'error': 'Agent ID required'}
    
    try:
        agent = Agent.objects.get(agent_id=agent_id)
        
        suspicious_response = data.get('response_text', """
        [SUSPICIOUS] This response contains unusual patterns and abnormal behavior.
        It includes repetitive content, excessive special characters, and 
        deviates from the expected medical/technical language patterns.
        ### MALICIOUS CONTENT ###
        !@#$%^&*()_+{}|:"<>?~
        Repeating repeating repeating repeating.
        """)
        
        detected, message = AttackDetector.detect_model_substitution(
            agent=agent,
            response_text=suspicious_response,
            expected_behavior_pattern="medical"
        )
        
        return {
            'scenario': 'Model Substitution Attack',
            'status': 'attack_detected' if not detected else 'failed',
            'message': message,
            'attack_detected': not detected,
            'agent_name': agent.name,
            'agent_id': agent.agent_id,
            'entropy_score': AttackDetector._calculate_entropy(suspicious_response),
            'timestamp': timezone.now().isoformat()
        }
        
    except Agent.DoesNotExist:
        return {'error': 'Agent not found'}
    except Exception as e:
        return {'error': str(e)}


def execute_scenario_6_revocation(data):
    """Scenario 6: Revocation Attack"""
    agent_id = data.get('agent_id')
    if not agent_id:
        return {'error': 'Agent ID required'}
    
    try:
        agent = Agent.objects.get(agent_id=agent_id)
        
        governance, created = GovernanceContract.objects.get_or_create(
            agent=agent,
            defaults={'is_revoked': False}
        )
        governance.is_revoked = True
        governance.reason = "Test: Revocation attack scenario"
        governance.revoked_at = timezone.now()
        governance.save()
        
        authorized, message = AttackDetector.check_governance_revocation(agent)
        
        governance.is_revoked = False
        governance.save()
        
        return {
            'scenario': 'Revocation Attack',
            'status': 'attack_detected' if not authorized else 'failed',
            'message': message,
            'attack_detected': not authorized,
            'agent_name': agent.name,
            'agent_id': agent.agent_id,
            'revoked': True,
            'timestamp': timezone.now().isoformat()
        }
        
    except Agent.DoesNotExist:
        return {'error': 'Agent not found'}
    except Exception as e:
        return {'error': str(e)}


def get_attack_logs(request):
    """Get all attack logs"""
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    try:
        user = Users.objects.get(id=request.session.get('user_id'))
    except Users.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})
    
    if user.role != 'admin':
        return JsonResponse({'success': False, 'message': 'Admin access required'})
    
    logs = AttackLog.objects.all().order_by('-detected_at')[:50]
    data = []
    for log in logs:
        data.append({
            'id': log.id,
            'attack_type': log.get_attack_type_display(),
            'severity': log.get_severity_display(),
            'proof_id': log.proof_id,
            'agent_id': log.agent_id,
            'description': log.description,
            'detected_at': log.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_resolved': log.is_resolved,
        })
    
    return JsonResponse({'success': True, 'logs': data})


def get_agents_api(request):
    """API endpoint to get agents for attack testing"""
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    agents = Agent.objects.filter(status='active').values('agent_id', 'name', 'id')
    return JsonResponse({'success': True, 'agents': list(agents)})


def get_recent_proofs_api(request):
    """API endpoint to get recent proofs for attack testing"""
    if not request.session.get('is_authenticated', False):
        return JsonResponse({'success': False, 'message': 'Not authenticated'})
    
    proofs = PoCAProof.objects.all().order_by('-created_at')[:10].values('proof_id')
    return JsonResponse({'success': True, 'proofs': list(proofs)})