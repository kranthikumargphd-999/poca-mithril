from django.db import models
from django.contrib.auth.hashers import make_password, check_password

# Create your models here.
# 1. USERS
class Users(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('user', 'End User'),
    ]
    
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    profile_image = models.ImageField(
        upload_to='profile_images/', 
        blank=True, 
        null=True, 
        default='profile_images/default.png')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'users'
        
    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
    def __str__(self):
        return f"{self.username} ({self.role})"


# 2. AI AGENT
class Agent(models.Model):
    PROVIDER_CHOICES = [
        ('openai', 'OpenAI'),
        ('groq', 'Groq'),
        ('huggingface', 'Hugging Face'),
        ('ollama', 'Ollama (Local)'),
    ]
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    agent_id = models.CharField(max_length=20, unique=True, editable=False)  # AGT-0001
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    llm_provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    model_name = models.CharField(max_length=100)
    api_key_encrypted = models.TextField()
    
    did = models.CharField(max_length=120, unique=True, editable=False)
    public_key = models.TextField()
    private_key_encrypted = models.TextField()
    model_hash = models.CharField(max_length=80, editable=False)
    
    registration_tx_hash = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    
    registered_by = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True, related_name='agents_registered')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'agents'
        
    def __str__(self):
        return f"{self.agent_id} — {self.name}"


# 3. POCA PROOF (Novel 1)
class PoCAProof(models.Model):
    proof_id = models.CharField(max_length=20, unique=True, editable=False)  # RESP-0001
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='proofs')
    submitted_by = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='queries')
    
    query_text = models.TextField()
    ai_response = models.TextField()
    
    context_hash = models.CharField(max_length=80)
    model_hash = models.CharField(max_length=80)
    safety_score = models.FloatField(default=0.0)

    # Timestamp included in the canonical PoCA signature.
    attestation_timestamp = models.DateTimeField(
        null=True,
        blank=True,
    )

    signature = models.TextField()

    accepted_at = models.DateTimeField(
        null=True,
        blank=True,
        editable=False,
    )
    
    is_batched = models.BooleanField(default=False)
    batch = models.ForeignKey('MithrilBatch',on_delete=models.SET_NULL, null=True, blank=True, related_name='proofs')
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'poca_proofs'
        
    def __str__(self):
        return self.proof_id


# 4. MITHRIL BATCH (Novel 2)
class MithrilBatch(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('anchored', 'Anchored On-Chain'),
        ('failed', 'Failed'),
    ]
    
    batch_id = models.CharField(max_length=20, unique=True, editable=False)  # BATCH-0001
    merkle_root = models.CharField(max_length=80)
    aggregated_signature = models.TextField()
    num_proofs = models.PositiveIntegerField()
    
    tx_hash = models.CharField(max_length=100, blank=True, null=True)
    block_number = models.PositiveIntegerField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    anchored_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'mithril_batches'
        
    def __str__(self):
        return f"{self.batch_id} ({self.num_proofs} proofs)"


# 5. BLOCKCHAIN TRANSACTION LOG
class BlockchainTransaction(models.Model):
    TX_TYPE_CHOICES = [
        ('did_registration', 'DID Registration'),
        ('batch_anchor', 'Mithril Batch Anchor'),
    ]
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]
    
    tx_hash = models.CharField(max_length=100, unique=True)
    tx_type = models.CharField(max_length=20, choices=TX_TYPE_CHOICES)
    
    related_agents = models.ManyToManyField(Agent,blank=True,related_name="blockchain_transactions")
    related_batch = models.ForeignKey(MithrilBatch, on_delete=models.SET_NULL, null=True, blank=True)
    
    block_number = models.PositiveIntegerField(blank=True, null=True)
    gas_used = models.PositiveIntegerField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='success')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'blockchain_transactions'
        
    def __str__(self):
        return f"{self.tx_hash[:12]}... ({self.tx_type})"



class AttackLog(models.Model):
    """Logs all detected attack attempts"""
    ATTACK_TYPES = [
        ('tampering', 'Response Tampering'),
        ('replay', 'Replay Attack'),
        ('unauthorized', 'Unauthorized Agent'),
        ('model_substitution', 'Model Substitution'),
        ('revocation', 'Revoked Agent'),
        ('normal', 'Normal Operation'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    attack_type = models.CharField(max_length=30, choices=ATTACK_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='medium')
    proof_id = models.CharField(max_length=20, null=True, blank=True)
    agent_id = models.CharField(max_length=20, null=True, blank=True)
    user_id = models.IntegerField(null=True, blank=True)
    description = models.TextField()
    details = models.JSONField(default=dict)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'attack_logs'
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.get_attack_type_display()} - {self.proof_id or 'N/A'}"


class AgentReputation(models.Model):
    """Tracks agent reputation based on behavior"""
    agent = models.OneToOneField(Agent, on_delete=models.CASCADE, related_name='reputation')
    score = models.FloatField(default=100.0)
    total_requests = models.IntegerField(default=0)
    successful_requests = models.IntegerField(default=0)
    failed_requests = models.IntegerField(default=0)
    attack_count = models.IntegerField(default=0)
    last_attack = models.DateTimeField(null=True, blank=True)
    is_flagged = models.BooleanField(default=False)
    flag_reason = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'agent_reputations'
    
    def __str__(self):
        return f"{self.agent.name} - Score: {self.score}"


class GovernanceContract(models.Model):
    """Simulated Governance Contract for revocation"""
    agent = models.OneToOneField(Agent, on_delete=models.CASCADE, related_name='governance')
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True, blank=True)
    reason = models.TextField(blank=True)
    
    class Meta:
        db_table = 'governance_contracts'
    
    def __str__(self):
        return f"{self.agent.name} - {'Revoked' if self.is_revoked else 'Active'}"



class ProcessedRequest(models.Model):
    request_id = models.CharField(max_length=128,unique=True,db_index=True,)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = "processed_requests"
        
    def __str__(self):
        return self.request_id
