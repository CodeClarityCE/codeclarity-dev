# PHP Support Implementation Plan for CodeClarity

## Executive Summary

This document outlines a comprehensive action plan to add PHP language support to CodeClarity, which currently only supports JavaScript analysis. The implementation will maintain backward compatibility while establishing a foundation for future multi-language support.

## Implementation Phases

### Phase 1: Backend Plugin Development
**Goal:** Create PHP-specific analysis plugins parallel to existing JavaScript plugins

#### 1.1 Create php-sbom Plugin
**Based on:** `backend/plugins/js-sbom/`

**Tasks:**
- [ ] Duplicate js-sbom plugin structure to create php-sbom
- [ ] Implement Composer manifest detection (composer.json, composer.lock)
- [ ] Create PHP-specific parser for Composer lock files
- [ ] Adapt SBOM generation for PHP package ecosystem
- [ ] Support multiple PHP frameworks (Laravel, Symfony, WordPress plugins)
- [ ] Add support for PHAR archives and vendored dependencies

**Key Files to Create:**
- `backend/plugins/php-sbom/main.go`
- `backend/plugins/php-sbom/src/run.go`
- `backend/plugins/php-sbom/src/parser/composer_parser.go`
- `backend/plugins/php-sbom/src/project_finder/php_finder.go`
- `backend/plugins/php-sbom/config.json`

**Technical Considerations:**
- Parse composer.lock for exact versions
- Handle autoload configurations
- Support PHP version constraints
- Extract development vs production dependencies

#### 1.2 Adapt js-vuln-finder to Multi-Language
**Goal:** Refactor to support both JavaScript and PHP vulnerabilities

**Tasks:**
- [ ] Rename plugin to `vuln-finder` (remove js- prefix)
- [ ] Add language parameter to plugin configuration
- [ ] Implement language-agnostic vulnerability matching
- [ ] Support multiple SBOM input formats
- [ ] Add PHP-specific vulnerability sources (PHP Security Database)

**Refactoring Approach:**
```go
// Change from:
vulnerabilities.Start(project.Url, sbom, "JS", start, args.knowledge)
// To:
vulnerabilities.Start(project.Url, sbom, sbom.Language, start, args.knowledge)
```

#### 1.3 Adapt js-license to Multi-Language
**Goal:** Support license detection for multiple languages

**Tasks:**
- [ ] Rename plugin to `license-checker` (remove js- prefix)
- [ ] Add Packagist license format support
- [ ] Implement SPDX license detection for PHP
- [ ] Support composer.json license fields
- [ ] Handle PHP-specific license patterns

### Phase 2: Knowledge Service Enhancement
**Goal:** Import and manage PHP vulnerability data

#### 2.1 Database Schema Updates
**Tasks:**
- [ ] Create language-agnostic package version tables
- [ ] Add PHP-specific tables for Packagist data
- [ ] Update vulnerability tables to support multiple ecosystems
- [ ] Create migration scripts for existing data

**New Database Tables:**
```sql
-- Generic package version table
CREATE TABLE package_version (
    id UUID PRIMARY KEY,
    ecosystem VARCHAR(50), -- 'npm', 'packagist', 'pypi', etc.
    package_name VARCHAR(255),
    version VARCHAR(100),
    metadata JSONB,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- PHP-specific extension
CREATE TABLE php_package_metadata (
    package_version_id UUID REFERENCES package_version(id),
    php_version_constraint VARCHAR(100),
    composer_type VARCHAR(50), -- 'library', 'project', 'metapackage'
    autoload JSONB,
    PRIMARY KEY (package_version_id)
);
```

#### 2.2 Vulnerability Data Sources
**Tasks:**
- [ ] Integrate PHP Security Advisories Database
- [ ] Add Packagist vulnerability feed
- [ ] Support CVE entries for PHP core and extensions
- [ ] Implement PHP-specific CPE matching
- [ ] Add FriendsOfPHP Security Advisories

**Implementation:**
- Create `backend/services/knowledge/src/sources/php/` directory
- Implement Packagist API client
- Add PHP vulnerability importers

#### 2.3 Package Follower Updates
**Tasks:**
- [ ] Add Packagist.org package tracking
- [ ] Implement Composer registry monitoring
- [ ] Support private Composer repositories
- [ ] Track PHP extension updates

### Phase 3: API Adaptations
**Goal:** Update API to handle multi-language analysis

#### 3.1 Analyzer Entity Updates
**Tasks:**
- [ ] Add language field to Analyzer entity
- [ ] Create language-specific analyzer templates
- [ ] Update analyzer creation endpoints
- [ ] Support multi-language analyzers

**API Changes:**
```typescript
// analyzer.entity.ts
export class Analyzer {
    // ... existing fields
    @Column({ type: 'varchar', array: true, default: ['javascript'] })
    supported_languages: string[];
    
    @Column({ type: 'jsonb', nullable: true })
    language_config: {
        javascript?: { plugins: string[] },
        php?: { plugins: string[] }
    };
}
```

#### 3.2 Analysis Workflow Updates
**Tasks:**
- [ ] Add language detection in analysis initialization
- [ ] Route to appropriate language plugins
- [ ] Update result aggregation for multi-language projects
- [ ] Support polyglot repositories

#### 3.3 New API Endpoints
**Tasks:**
- [ ] Create `/api/languages` endpoint for supported languages
- [ ] Add `/api/analyzers/templates/:language` for language-specific templates
- [ ] Update `/api/analyses/create` to accept language parameter
- [ ] Add language filtering to results endpoints

### Phase 4: Frontend Adaptations
**Goal:** Display PHP analysis results appropriately

#### 4.1 Dynamic Plugin Tab System
**Tasks:**
- [ ] Replace hardcoded plugin tabs with dynamic detection
- [ ] Create language-aware result components
- [ ] Add PHP-specific result visualizations
- [ ] Support mixed-language project displays

**Frontend Changes:**
```vue
<!-- ResultsView.vue -->
<script setup>
// Change from static tabs to dynamic
const availablePlugins = computed(() => {
    return results.value
        .map(r => r.plugin_name)
        .filter(unique);
});

const pluginTabs = computed(() => {
    return availablePlugins.value.map(plugin => ({
        name: plugin,
        label: getPluginLabel(plugin),
        component: getPluginComponent(plugin)
    }));
});
</script>
```

#### 4.2 PHP-Specific Components
**Tasks:**
- [ ] Create ComposerDependencyTree component
- [ ] Add PHP vulnerability display component
- [ ] Implement PHP license compliance view
- [ ] Create PHP-specific fix suggestions component

#### 4.3 Language Selector UI
**Tasks:**
- [ ] Add language selector in analysis creation
- [ ] Display detected languages in project view
- [ ] Add language filters in dashboard
- [ ] Create language statistics widgets

### Phase 5: Testing & Integration
**Goal:** Ensure robust PHP support across the platform

#### 5.1 Test Repository Setup
**Tasks:**
- [ ] Create PHP test repositories with various frameworks
- [ ] Include repositories with known vulnerabilities
- [ ] Add multi-language test projects
- [ ] Setup automated test pipelines

**Test Scenarios:**
- Laravel application with mixed npm/composer dependencies
- WordPress plugin with security issues
- Symfony project with license compliance issues
- Legacy PHP application with outdated dependencies

#### 5.2 Plugin Testing
**Tasks:**
- [ ] Unit tests for PHP parsers
- [ ] Integration tests for php-sbom
- [ ] Vulnerability detection accuracy tests
- [ ] License detection validation
- [ ] Performance benchmarks

#### 5.3 End-to-End Testing
**Tasks:**
- [ ] Complete analysis workflow for PHP projects
- [ ] Multi-language project analysis
- [ ] API endpoint testing with PHP data
- [ ] Frontend display validation
- [ ] Migration testing for existing data

### Phase 6: Documentation & Deployment
**Goal:** Document and deploy PHP support

#### 6.1 Documentation Updates
**Tasks:**
- [ ] Update CLAUDE.md with PHP commands
- [ ] Create PHP plugin development guide
- [ ] Document PHP-specific configuration
- [ ] Add PHP troubleshooting guide
- [ ] Update API documentation

#### 6.2 Migration Strategy
**Tasks:**
- [ ] Create database migration scripts
- [ ] Update Docker images with PHP support
- [ ] Modify deployment scripts
- [ ] Create rollback procedures
- [ ] Update CI/CD pipelines

#### 6.3 Configuration Updates
**Tasks:**
- [ ] Update default analyzers to include PHP
- [ ] Add PHP-specific environment variables
- [ ] Configure PHP vulnerability update schedules
- [ ] Setup PHP package monitoring

## Implementation Timeline

### Week 1-2: Foundation
- Set up development environment for PHP plugins
- Create php-sbom plugin structure
- Implement basic Composer parsing

### Week 3-4: Core Plugin Development
- Complete php-sbom implementation
- Begin vuln-finder refactoring
- Start license-checker adaptation

### Week 5-6: Knowledge Service
- Database schema updates
- PHP vulnerability data integration
- Package follower updates

### Week 7-8: API Integration
- API entity updates
- New endpoints implementation
- Testing API changes

### Week 9-10: Frontend Development
- Dynamic plugin system
- PHP-specific components
- UI/UX refinements

### Week 11-12: Testing & Refinement
- Comprehensive testing
- Bug fixes
- Performance optimization

### Week 13-14: Documentation & Deployment
- Documentation updates
- Deployment preparation
- Production rollout

## Technical Decisions

### 1. Plugin Architecture
**Decision:** Create separate PHP plugins initially, then refactor to language-agnostic plugins in Phase 2
**Rationale:** Allows faster initial implementation while learning PHP-specific requirements

### 2. Database Strategy
**Decision:** Use language-agnostic tables with language-specific extension tables
**Rationale:** Maintains backward compatibility while supporting extensibility

### 3. Frontend Approach
**Decision:** Implement dynamic plugin detection rather than hardcoded language support
**Rationale:** Enables easy addition of future languages without frontend changes

## Risk Mitigation

### Technical Risks
1. **Database Migration Complexity**
   - Mitigation: Comprehensive backup strategy, staged rollout
   
2. **Performance Impact**
   - Mitigation: Implement caching, optimize queries, benchmark regularly

3. **Backward Compatibility**
   - Mitigation: Maintain js- prefixed plugins during transition period

### Operational Risks
1. **Knowledge Database Size**
   - Mitigation: Implement data retention policies, optimize storage

2. **Analysis Time Increase**
   - Mitigation: Parallel plugin execution, result caching

## Success Criteria

1. **Functional Requirements**
   - [ ] Successfully analyze PHP projects
   - [ ] Detect PHP vulnerabilities accurately
   - [ ] Generate PHP SBOM compatible with industry standards
   - [ ] Identify license compliance issues

2. **Performance Requirements**
   - [ ] PHP analysis completes within 2x JavaScript analysis time
   - [ ] Database queries remain under 100ms
   - [ ] Frontend responsiveness maintained

3. **Quality Requirements**
   - [ ] 90%+ vulnerability detection accuracy
   - [ ] Zero regression in JavaScript support
   - [ ] All tests passing

## Next Steps

1. **Immediate Actions**
   - Review and approve this plan
   - Set up PHP development environment
   - Begin php-sbom plugin development

2. **Team Coordination**
   - Assign team members to phases
   - Schedule weekly progress reviews
   - Establish communication channels

3. **Resource Allocation**
   - Provision development servers
   - Allocate database resources
   - Setup CI/CD pipelines

## Appendix

### A. PHP Ecosystem Overview
- **Package Manager:** Composer
- **Registry:** Packagist.org
- **Lock File:** composer.lock
- **Manifest:** composer.json
- **Vendor Directory:** vendor/

### B. PHP Security Resources
- PHP Security Advisories Database
- FriendsOfPHP Security Advisories
- Snyk PHP Vulnerability Database
- CVE Database (PHP entries)
- OWASP PHP Security Guide

### C. Common PHP Frameworks
- Laravel
- Symfony
- Zend/Laminas
- CodeIgniter
- Yii
- Slim
- WordPress (CMS)
- Drupal (CMS)
- Joomla (CMS)

### D. PHP License Types
- MIT
- BSD
- Apache 2.0
- GPL (various versions)
- LGPL
- PHP License
- Proprietary/Commercial

---

*This action plan provides a structured approach to adding PHP support to CodeClarity. Each phase builds upon the previous one, ensuring a stable and maintainable implementation. The plan can be adjusted based on resource availability and priority changes.*